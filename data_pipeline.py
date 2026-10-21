"""
CVE → CWE → CAPEC → ATT&CK → Mitigation data collection pipeline.

Pulls from authoritative MITRE / NIST sources and joins them into a single
enriched DataFrame whose schema matches the synthetic generator used in
`neural_networks_lecture.ipynb`, so the existing classifiers can be retrained
on real data with no code changes.

Sources
-------
* CVE          -> NVD API 2.0 (https://services.nvd.nist.gov/rest/json/cves/2.0)
* CWE catalog  -> https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
* CAPEC        -> https://capec.mitre.org/data/xml/capec_latest.xml
                  (uses Related_Weaknesses and Taxonomy_Mappings to ATT&CK)
* ATT&CK       -> https://raw.githubusercontent.com/mitre-attack/attack-stix-data/
                  master/enterprise-attack/enterprise-attack.json
                  (STIX 2.1 bundle; relationship_type='mitigates' links
                  course-of-action -> attack-pattern)

Offline / rate-limit resilience
-------------------------------
All network I/O goes through ``SqliteCache`` which keys on the full URL +
query-string. Re-running the pipeline is free after the first pull.
``NVDClient`` enforces the documented rate limits (5/30s without a key,
50/30s with one) via a simple rolling-window sleep.
"""

from __future__ import annotations

import io
import json
import logging
import os
import sqlite3
import time
import zipfile
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator
from urllib.parse import urlencode
from xml.etree import ElementTree as ET

import pandas as pd
import requests

log = logging.getLogger("data_pipeline")

# ---------------------------------------------------------------------------
# URLs
# ---------------------------------------------------------------------------
NVD_BASE          = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CWE_XML_ZIP_URL   = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
CAPEC_XML_URL     = "https://capec.mitre.org/data/xml/capec_latest.xml"
ATTACK_STIX_URL   = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)

# XML namespaces
NS_CAPEC = {"capec": "http://capec.mitre.org/capec-3"}
NS_CWE   = {"cwe":   "http://cwe.mitre.org/cwe-7"}  # catalogue uses cwe-7


# ===========================================================================
# Caching
# ===========================================================================
class SqliteCache:
    """Tiny blob cache keyed by URL. Stores response bytes + fetched_at."""

    def __init__(self, path: str | os.PathLike = "pipeline_cache.sqlite"):
        self.path = str(path)
        self._conn = sqlite3.connect(self.path)
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS blob (
                   key TEXT PRIMARY KEY,
                   fetched_at TEXT NOT NULL,
                   content_type TEXT,
                   payload BLOB NOT NULL
               )"""
        )
        self._conn.commit()

    def get(self, key: str) -> bytes | None:
        row = self._conn.execute(
            "SELECT payload FROM blob WHERE key = ?", (key,)
        ).fetchone()
        return row[0] if row else None

    def put(self, key: str, payload: bytes, content_type: str = "") -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO blob VALUES (?, ?, ?, ?)",
            (key, datetime.now(timezone.utc).isoformat(), content_type, payload),
        )
        self._conn.commit()

    def has(self, key: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM blob WHERE key = ?", (key,)
        ).fetchone()
        return row is not None

    def close(self) -> None:
        self._conn.close()


def _cached_get(
    url: str,
    *,
    cache: SqliteCache | None,
    params: dict | None = None,
    headers: dict | None = None,
    timeout: int = 60,
) -> bytes:
    """GET with cache. Returns raw bytes."""
    key = url + ("?" + urlencode(sorted(params.items())) if params else "")
    if cache is not None:
        blob = cache.get(key)
        if blob is not None:
            log.debug("cache hit: %s", key)
            return blob
    log.info("fetching %s", key)
    resp = requests.get(url, params=params, headers=headers or {}, timeout=timeout)
    resp.raise_for_status()
    if cache is not None:
        cache.put(key, resp.content, resp.headers.get("Content-Type", ""))
    return resp.content


def _normalize_nvd_query_filters(filters: dict[str, Any]) -> dict[str, Any]:
    """Align filter values with NVD 2.0 query semantics.

    ``hasKev`` must be the empty string to restrict results to the CISA KEV
    catalog; values like ``"1"`` or ``True`` become ``?hasKev=1`` and the
    API responds with 404.
    """
    out = dict(filters)
    if "hasKev" not in out:
        return out
    v = out["hasKev"]
    if v in (False, 0, "0", "false", "False", "no", "n", "off"):
        del out["hasKev"]
        return out
    if v is True or v == 1 or (
        isinstance(v, str) and v.strip().lower() in {"1", "true", "yes", "y", "on"}
    ):
        out["hasKev"] = ""
    return out


# ===========================================================================
# NVD CVE client
# ===========================================================================
@dataclass
class NVDRateLimiter:
    """Rolling-window limiter matching NVD's documented quotas."""

    max_calls: int = 5         # 5 without api key, 50 with
    window_sec: float = 30.0

    def __post_init__(self) -> None:
        self._stamps: deque[float] = deque()

    def wait(self) -> None:
        now = time.monotonic()
        while self._stamps and (now - self._stamps[0]) > self.window_sec:
            self._stamps.popleft()
        if len(self._stamps) >= self.max_calls:
            sleep_for = self.window_sec - (now - self._stamps[0]) + 0.1
            if sleep_for > 0:
                log.info("NVD rate-limit sleep %.1fs", sleep_for)
                time.sleep(sleep_for)
        self._stamps.append(time.monotonic())


class NVDClient:
    """Paginated NVD 2.0 CVE API.

    Parameters
    ----------
    api_key : str, optional
        If supplied, sent as ``apiKey`` header and the rate-limit window
        is relaxed from 5/30s to 50/30s per NVD docs.
    cache : SqliteCache, optional
        When provided, every page response is cached by (url, params).
    results_per_page : int
        Page size. NVD max is 2000; default 2000 is most efficient.
    """

    def __init__(
        self,
        api_key: str | None = None,
        cache: SqliteCache | None = None,
        results_per_page: int = 2000,
    ):
        self.api_key = api_key
        self.cache = cache
        self.results_per_page = results_per_page
        self.limiter = NVDRateLimiter(
            max_calls=50 if api_key else 5, window_sec=30.0
        )
        self._headers = {"apiKey": api_key} if api_key else {}

    def _get_page(self, params: dict) -> dict:
        # Cache short-circuits before hitting the limiter.
        key = NVD_BASE + "?" + urlencode(sorted(params.items()))
        if self.cache is not None and self.cache.has(key):
            return json.loads(self.cache.get(key).decode("utf-8"))
        self.limiter.wait()
        for attempt in range(5):
            try:
                payload = _cached_get(
                    NVD_BASE,
                    cache=self.cache,
                    params=params,
                    headers=self._headers,
                    timeout=60,
                )
                return json.loads(payload.decode("utf-8"))
            except requests.HTTPError as e:
                status = e.response.status_code if e.response is not None else 0
                if status in (403, 429, 503) and attempt < 4:
                    backoff = 6.0 * (attempt + 1)
                    log.warning("NVD %s, backing off %.1fs", status, backoff)
                    time.sleep(backoff)
                    continue
                raise
            except (requests.exceptions.ChunkedEncodingError,
                    requests.exceptions.ConnectionError) as e:
                # NVD occasionally drops connections mid-stream; retry with backoff
                if attempt < 4:
                    backoff = 5.0 * (attempt + 1)
                    log.warning("NVD connection error (%s), retrying in %.1fs", e, backoff)
                    time.sleep(backoff)
                    continue
                raise
        raise RuntimeError("NVD: exceeded retry budget")

    def iter_cves(self, **filters: Any) -> Iterator[dict]:
        """Yield raw CVE item dicts matching the given NVD query parameters.

        Any kwargs are passed straight through (e.g. ``cweId='CWE-79'``,
        ``hasKev=''`` for KEV-only (empty string; ``hasKev='1'`` is invalid),
        ``pubStartDate='2024-01-01T00:00:00.000'``,
        ``pubEndDate='2024-01-31T23:59:59.999'``, ``keywordSearch='Apache'``).
        Handles pagination automatically.
        """
        filters = _normalize_nvd_query_filters(dict(filters))
        start = 0
        while True:
            params = {k: v for k, v in filters.items() if v is not None}
            params["startIndex"] = start
            params["resultsPerPage"] = self.results_per_page
            page = self._get_page(params)
            vulns = page.get("vulnerabilities", [])
            for v in vulns:
                yield v
            total = page.get("totalResults", 0)
            start += len(vulns)
            log.info("NVD page: got %d (cumulative %d / %d)", len(vulns), start, total)
            if start >= total or not vulns:
                return

    def iter_cves_windowed(
        self,
        pub_start: str,
        pub_end:   str,
        window_days: int = 120,
        **extra_filters: Any,
    ) -> Iterator[dict]:
        """Yield CVEs across an arbitrary date range by chunking into windows.

        NVD enforces a hard 120-day limit on pubStartDate/pubEndDate ranges.
        This method splits the range into ``window_days``-sized chunks and
        calls ``iter_cves`` for each, so callers can ask for multi-year pulls
        without worrying about the limit.

        Parameters
        ----------
        pub_start : str   e.g. '2018-01-01T00:00:00.000'
        pub_end   : str   e.g. '2024-12-31T23:59:59.999'
        window_days : int  Max days per NVD request (default 120 = NVD limit).
        **extra_filters   Any additional NVD filter kwargs (noRejected='', etc.)
        """
        fmt = "%Y-%m-%dT%H:%M:%S.%f"
        # Allow the shorter 'Z' suffix used by some callers
        def _parse(s: str) -> datetime:
            return datetime.strptime(s.rstrip("Z").ljust(23, "0"), fmt)

        cursor = _parse(pub_start)
        end_dt = _parse(pub_end)
        window  = timedelta(days=window_days)
        one_ms  = timedelta(milliseconds=1)

        while cursor <= end_dt:
            chunk_end = min(cursor + window - one_ms, end_dt)
            chunk_start_s = cursor.strftime(fmt)[:-3]
            chunk_end_s   = chunk_end.strftime(fmt)[:-3]
            log.info("windowed fetch %s → %s", chunk_start_s, chunk_end_s)
            yield from self.iter_cves(
                pubStartDate=chunk_start_s,
                pubEndDate=chunk_end_s,
                **extra_filters,
            )
            cursor = chunk_end + one_ms


def _parse_cvss_vector(vector: str | None) -> dict:
    """Decompose a CVSS v3.x vector string into individual metric columns.

    e.g. 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
    Returns None for all keys when vector is absent or v2 (different schema).
    """
    keys = {
        "AV": "cvss_av",    # Attack Vector:         N A L P
        "AC": "cvss_ac",    # Attack Complexity:     L H
        "PR": "cvss_pr",    # Privileges Required:   N L H
        "UI": "cvss_ui",    # User Interaction:      N R
        "S":  "cvss_scope", # Scope:                 U C
        "C":  "cvss_c",     # Confidentiality:       N L H
        "I":  "cvss_i",     # Integrity:             N L H
        "A":  "cvss_a",     # Availability:          N L H
    }
    out = {v: None for v in keys.values()}
    if not vector or not vector.startswith("CVSS:3"):
        return out
    for part in vector.split("/")[1:]:
        if ":" in part:
            k, v = part.split(":", 1)
            if k in keys:
                out[keys[k]] = v
    return out


def parse_cve_item(item: dict) -> dict:
    """Flatten one NVD ``vulnerabilities[i]`` entry into a tabular record."""
    cve = item.get("cve", item)  # tolerate both shapes

    cve_id = cve.get("id", "")

    # English description
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break

    # CWE IDs (skip NVD placeholder values)
    cwe_ids: list[str] = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            val = d.get("value", "")
            if val.startswith("CWE-"):
                cwe_ids.append(val)
    cwe_ids = sorted(set(cwe_ids))

    # CVSS: prefer v3.1 > v3.0 > v2
    metrics = cve.get("metrics", {})
    cvss_score: float | None = None
    cvss_severity: str | None = None
    cvss_vector: str | None = None
    cvss_version: str | None = None
    exploitability_score: float | None = None
    impact_score: float | None = None
    for key, ver in (
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2",  "2.0"),
    ):
        arr = metrics.get(key) or []
        if arr:
            m = arr[0]["cvssData"]
            cvss_score    = m.get("baseScore")
            cvss_severity = m.get("baseSeverity") or arr[0].get("baseSeverity")
            cvss_vector   = m.get("vectorString")
            cvss_version  = ver
            exploitability_score = arr[0].get("exploitabilityScore")
            impact_score         = arr[0].get("impactScore")
            break

    # CVSS vector decomposition (v3.x only)
    vector_components = _parse_cvss_vector(cvss_vector)

    # KEV: CISA fields are promoted to top-level CVE when on KEV catalog
    is_kev = "cisaExploitAdd" in cve

    # Reference signal: patch availability and public exploit presence
    refs = cve.get("references", [])
    has_patch   = any("Patch"   in r.get("tags", []) for r in refs)
    has_exploit = any("Exploit" in r.get("tags", []) for r in refs)

    # Affected products (best-effort from CPE configurations)
    vendors: set[str] = set()
    products: set[str] = set()
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                cpe = m.get("criteria", "")
                # cpe:2.3:part:vendor:product:version:...
                parts = cpe.split(":")
                if len(parts) >= 5:
                    if parts[3] != "*":
                        vendors.add(parts[3])
                    if parts[3] != "*" and parts[4] != "*":
                        products.add(f"{parts[3]} {parts[4]}")

    return {
        "cve_id":               cve_id,
        "description":          desc,
        "cwe_ids":              cwe_ids,
        "cwe_id":               cwe_ids[0] if cwe_ids else None,
        "cvss_score":           cvss_score,
        "cvss_severity":        cvss_severity,
        "cvss_vector":          cvss_vector,
        "cvss_version":         cvss_version,
        "exploitability_score": exploitability_score,
        "impact_score":         impact_score,
        **vector_components,
        "is_kev":               is_kev,
        "has_patch":            has_patch,
        "has_exploit":          has_exploit,
        "published":            cve.get("published"),
        "last_modified":        cve.get("lastModified"),
        "vuln_status":          cve.get("vulnStatus"),
        "vendors":              sorted(vendors),
        "products":             sorted(products),
    }


def cves_to_dataframe(items: Iterable[dict]) -> pd.DataFrame:
    """Parse an iterable of raw NVD items into a DataFrame."""
    rows = [parse_cve_item(it) for it in items]
    df = pd.DataFrame(rows)
    # Coerce types that make downstream ML easier
    if "cvss_score" in df:
        df["cvss_score"] = pd.to_numeric(df["cvss_score"], errors="coerce")
    if "published" in df:
        df["published"] = pd.to_datetime(df["published"], errors="coerce", utc=True)
    return df


# ===========================================================================
# CWE catalog
# ===========================================================================
def fetch_cwe_xml(cache: SqliteCache | None = None) -> bytes:
    """Download the CWE catalogue zip, return the inner XML bytes.

    The CWE team publishes a single zip containing ``cwec_v<ver>.xml``.
    """
    raw = _cached_get(CWE_XML_ZIP_URL, cache=cache)
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        for name in zf.namelist():
            if name.endswith(".xml"):
                return zf.read(name)
    raise RuntimeError("cwec zip has no .xml member")


def parse_cwe(xml_bytes: bytes) -> pd.DataFrame:
    """Parse CWE XML into a DataFrame.

    Columns: ``cwe_id`` (e.g. 'CWE-79'), ``name``, ``abstraction``, ``status``,
    ``description``, ``extended_description``.
    """
    root = ET.fromstring(xml_bytes)
    # Detect namespace from root tag: "{http://cwe.mitre.org/cwe-7}Weakness_Catalog"
    if root.tag.startswith("{"):
        uri = root.tag[1:].split("}")[0]
        ns = {"cwe": uri}
    else:
        ns = {}

    rows = []
    xpath_weak = ".//cwe:Weaknesses/cwe:Weakness" if ns else ".//Weaknesses/Weakness"
    for w in root.findall(xpath_weak, ns):
        cwe_id = w.get("ID")
        name = w.get("Name")
        absn = w.get("Abstraction")
        status = w.get("Status")

        def _text(tag: str) -> str:
            xp = f"cwe:{tag}" if ns else tag
            node = w.find(xp, ns)
            if node is None:
                return ""
            # Concatenate all inner text (may have xhtml children)
            return " ".join(t.strip() for t in node.itertext() if t.strip())

        rows.append(
            {
                "cwe_id": f"CWE-{cwe_id}",
                "name": name,
                "abstraction": absn,
                "status": status,
                "description": _text("Description"),
                "extended_description": _text("Extended_Description"),
            }
        )
    return pd.DataFrame(rows)


# ===========================================================================
# CAPEC
# ===========================================================================
def parse_capec(
    xml_bytes_or_path: bytes | str | os.PathLike,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Parse a CAPEC XML bundle.

    Returns
    -------
    patterns_df   : columns ``capec_id``, ``name``, ``abstraction``, ``status``,
                    ``description``, ``likelihood``, ``severity``.
    capec_cwe_df  : long-form rows of ``(capec_id, cwe_id)``.
    capec_attack_df : long-form rows of ``(capec_id, attack_id, attack_name)``
                      with IDs normalized to ``T####`` or ``T####.###``.
    """
    if isinstance(xml_bytes_or_path, (bytes, bytearray)):
        root = ET.fromstring(xml_bytes_or_path)
    else:
        root = ET.parse(str(xml_bytes_or_path)).getroot()

    ns = NS_CAPEC

    patterns: list[dict] = []
    cwe_links: list[dict] = []
    attack_links: list[dict] = []

    for p in root.findall("capec:Attack_Patterns/capec:Attack_Pattern", ns):
        pid = p.get("ID")
        capec_id = f"CAPEC-{pid}"

        desc = p.find("capec:Description", ns)
        desc_txt = " ".join(t.strip() for t in desc.itertext() if t.strip()) if desc is not None else ""

        lik = p.find("capec:Likelihood_Of_Attack", ns)
        sev = p.find("capec:Typical_Severity", ns)

        patterns.append(
            {
                "capec_id":     capec_id,
                "name":         p.get("Name"),
                "abstraction":  p.get("Abstraction"),
                "status":       p.get("Status"),
                "description":  desc_txt,
                "likelihood":   lik.text if lik is not None else None,
                "severity":     sev.text if sev is not None else None,
            }
        )

        rw = p.find("capec:Related_Weaknesses", ns)
        if rw is not None:
            for w in rw.findall("capec:Related_Weakness", ns):
                cwe = w.get("CWE_ID")
                if cwe:
                    cwe_links.append(
                        {"capec_id": capec_id, "cwe_id": f"CWE-{cwe}"}
                    )

        tm = p.find("capec:Taxonomy_Mappings", ns)
        if tm is not None:
            for mapping in tm.findall("capec:Taxonomy_Mapping", ns):
                if mapping.get("Taxonomy_Name") != "ATTACK":
                    continue
                entry = mapping.find("capec:Entry_ID", ns)
                name_e = mapping.find("capec:Entry_Name", ns)
                if entry is None or not entry.text:
                    continue
                raw = entry.text.strip()
                # CAPEC stores '1059.007' — normalize to 'T1059.007'
                attack_id = raw if raw.startswith("T") else f"T{raw}"
                attack_links.append(
                    {
                        "capec_id":   capec_id,
                        "attack_id":  attack_id,
                        "attack_name": name_e.text if name_e is not None else None,
                    }
                )

    return (
        pd.DataFrame(patterns),
        pd.DataFrame(cwe_links),
        pd.DataFrame(attack_links),
    )


# ===========================================================================
# ATT&CK (STIX 2.1)
# ===========================================================================
def fetch_attack_stix(cache: SqliteCache | None = None) -> dict:
    """Download the enterprise-attack STIX bundle."""
    raw = _cached_get(ATTACK_STIX_URL, cache=cache)
    return json.loads(raw.decode("utf-8"))


def _stix_external_id(obj: dict, source: str = "mitre-attack") -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == source:
            return ref.get("external_id")
    return None


def parse_attack(bundle: dict) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Parse a STIX 2.1 bundle.

    Returns
    -------
    techniques_df  : ``attack_id``, ``stix_id``, ``name``, ``description``,
                     ``is_subtechnique``, ``tactics``, ``platforms``.
    mitigations_df : ``mitigation_id``, ``stix_id``, ``name``, ``description``.
    mitigates_df   : ``mitigation_id``, ``attack_id`` (from STIX ``mitigates``
                     relationships linking course-of-action -> attack-pattern).
    """
    objs = bundle.get("objects", [])

    techniques: list[dict] = []
    mitigations: list[dict] = []
    stix_to_attack_id: dict[str, str] = {}
    stix_to_mitigation_id: dict[str, str] = {}

    for o in objs:
        if o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        t = o.get("type")
        if t == "attack-pattern":
            ext = _stix_external_id(o)
            if not ext:
                continue
            stix_to_attack_id[o["id"]] = ext
            tactics = [
                ph.get("phase_name")
                for ph in o.get("kill_chain_phases", [])
                if ph.get("kill_chain_name") == "mitre-attack"
            ]
            techniques.append(
                {
                    "attack_id":        ext,
                    "stix_id":          o["id"],
                    "name":             o.get("name"),
                    "description":      o.get("description", ""),
                    "is_subtechnique":  bool(o.get("x_mitre_is_subtechnique")),
                    "tactics":          tactics,
                    "platforms":        o.get("x_mitre_platforms", []),
                }
            )
        elif t == "course-of-action":
            ext = _stix_external_id(o)
            if not ext:
                continue
            stix_to_mitigation_id[o["id"]] = ext
            mitigations.append(
                {
                    "mitigation_id":  ext,
                    "stix_id":        o["id"],
                    "name":           o.get("name"),
                    "description":    o.get("description", ""),
                }
            )

    mitigates: list[dict] = []
    for o in objs:
        if o.get("type") != "relationship":
            continue
        if o.get("relationship_type") != "mitigates":
            continue
        src = o.get("source_ref")
        tgt = o.get("target_ref")
        if src in stix_to_mitigation_id and tgt in stix_to_attack_id:
            mitigates.append(
                {
                    "mitigation_id": stix_to_mitigation_id[src],
                    "attack_id":     stix_to_attack_id[tgt],
                }
            )

    return (
        pd.DataFrame(techniques),
        pd.DataFrame(mitigations),
        pd.DataFrame(mitigates),
    )


# ===========================================================================
# Optional CWE -> ATT&CK bridge for known coverage gaps
# ===========================================================================
# ATT&CK is post-compromise focused, so most web-application CWEs do NOT chain
# through a CAPEC that has a Taxonomy_Mapping to ATT&CK. In practice, teams
# using ATT&CK to reason about web vulns map them all to T1190 (Exploit
# Public-Facing Application) as the relevant initial-access technique.
#
# These mappings are heuristic, *not* from MITRE. They give downstream labels
# a non-empty chain so classifiers can still learn. Supply your own via
# ``build_unified(cwe_attack_bridge=...)`` to override.
DEFAULT_CWE_ATTACK_BRIDGE: dict[str, list[str]] = {
    # ── Web app / injection ───────────────────────────────────────────────────
    # CTID-derived (CVE evidence via center-for-threat-informed-defense/attack_to_cve)
    "CWE-79":  ["T1055", "T1059.007", "T1189", "T1204.001", "T1557"],   # XSS
    "CWE-89":  ["T1059", "T1190"],                                       # SQLi
    "CWE-78":  ["T1190", "T1203", "T1059.004"],                          # OS cmd injection
    "CWE-74":  ["T1059", "T1190"],                                       # Injection (generic)
    "CWE-77":  ["T1068", "T1133"],                                       # Command injection
    "CWE-94":  ["T1190", "T1203", "T1189", "T1059"],                     # Code injection
    "CWE-22":  ["T1190", "T1203", "T1083", "T1212", "T1005"],            # Path traversal
    "CWE-434": ["T1190", "T1505.003"],                                   # Unrestricted file upload
    "CWE-502": ["T1190", "T1203", "T1059"],                              # Unsafe deserialization
    "CWE-611": ["T1005", "T1552.001"],                                   # XXE
    # hand-written fallback (no CTID coverage)
    "CWE-352": ["T1204"],                                                # CSRF -> user execution

    # ── Memory corruption ─────────────────────────────────────────────────────
    # CTID-derived
    "CWE-119": ["T1203", "T1189", "T1204.002", "T1068", "T1190"],        # Buffer errors
    "CWE-120": ["T1190", "T1203", "T1055", "T1204.002"],                 # Classic buffer overflow
    "CWE-787": ["T1203", "T1189", "T1068", "T1204.002", "T1190"],        # Out-of-bounds write
    "CWE-416": ["T1203", "T1068", "T1189", "T1204.002"],                 # Use-after-free
    "CWE-362": ["T1189", "T1055", "T1068", "T1203"],                     # Race condition
    "CWE-843": ["T1189", "T1203", "T1190"],                              # Type confusion
    # hand-written fallback (no CTID coverage)
    "CWE-125": ["T1203"],                                                # Out-of-bounds read

    # ── Authentication / access control ──────────────────────────────────────
    # CTID-derived
    "CWE-287": ["T1068", "T1189", "T1203"],                              # Improper auth
    "CWE-306": ["T1190", "T1203"],                                       # Missing auth
    "CWE-284": ["T1189", "T1203", "T1190"],                              # Improper access control
    "CWE-269": ["T1068"],                                                # Improper privilege mgmt
    "CWE-200": ["T1068", "T1212", "T1548.002"],                          # Info exposure
    "CWE-255": ["T1003", "T1552.001"],                                   # Credential mgmt
    # hand-written fallback (no CTID coverage)
    "CWE-862": ["T1078"],                                                # Missing authorization
    "CWE-798": ["T1078"],                                                # Hard-coded credentials

    # ── Crypto / network ──────────────────────────────────────────────────────
    # CTID-derived
    "CWE-295": ["T1190", "T1203"],                                       # Cert validation
    "CWE-347": ["T1190", "T1539"],                                       # Improper signature verify
    # hand-written fallback (no CTID coverage)
    "CWE-327": ["T1557"],                                                # Broken crypto -> MitM

    # ── Input validation / misc ───────────────────────────────────────────────
    # CTID-derived
    "CWE-20":  ["T1190", "T1203", "T1499.004", "T1133", "T1189"],        # Improper input validation
    "CWE-693": ["T1189", "T1203"],                                       # Protection mechanism failure
}


def compute_coverage(
    cves_df:       pd.DataFrame,
    capec_cwe_df:  pd.DataFrame,
    capec_attack_df: pd.DataFrame,
    mitigates_df:  pd.DataFrame,
) -> pd.DataFrame:
    """Report, per CWE appearing in the CVE set, how many CAPECs exist, how
    many of those have an ATT&CK mapping, and whether a mitigation is reachable.
    Use this to decide whether to enable the CWE->ATT&CK bridge.
    """
    cwes = (
        cves_df["cwe_ids"].explode().dropna().unique().tolist()
        if "cwe_ids" in cves_df else []
    )
    rows = []
    for cwe in cwes:
        caps = capec_cwe_df[capec_cwe_df["cwe_id"] == cwe]["capec_id"].tolist()
        caps_with_attack = capec_attack_df[
            capec_attack_df["capec_id"].isin(caps)
        ]["capec_id"].nunique()
        reachable_attacks = capec_attack_df[
            capec_attack_df["capec_id"].isin(caps)
        ]["attack_id"].nunique()
        reachable_mitigs = mitigates_df[
            mitigates_df["attack_id"].isin(
                capec_attack_df[capec_attack_df["capec_id"].isin(caps)]["attack_id"]
            )
        ]["mitigation_id"].nunique()
        rows.append(
            {
                "cwe_id":           cwe,
                "n_cves":           int(cves_df["cwe_ids"].apply(lambda xs: cwe in (xs or [])).sum()),
                "n_capecs":         len(caps),
                "capecs_w_attack":  caps_with_attack,
                "attack_reachable": reachable_attacks,
                "mitig_reachable":  reachable_mitigs,
            }
        )
    return (
        pd.DataFrame(rows)
        .sort_values("n_cves", ascending=False)
        .reset_index(drop=True)
    )


# ===========================================================================
# Unified join
# ===========================================================================
def build_unified(
    cves_df:          pd.DataFrame,
    capec_cwe_df:     pd.DataFrame,
    capec_attack_df:  pd.DataFrame,
    mitigates_df:     pd.DataFrame,
    mitigations_df:   pd.DataFrame | None = None,
    techniques_df:    pd.DataFrame | None = None,
    cwe_attack_bridge: dict[str, list[str]] | None = None,
) -> pd.DataFrame:
    """Produce the per-CVE enriched frame.

    Schema (drop-in for the synthetic generator):
        cve_id, description, cwe_id, cwe_ids, cvss_score, cvss_severity,
        is_kev, published, products,
        capec_ids, attack_ids, mitigation_ids,
        attack_names, mitigation_names, attack_source

    ``attack_source`` flags each row as ``'capec'`` when the chain came through
    CAPEC, ``'bridge'`` when it came from the supplied CWE->ATT&CK fallback,
    or ``'none'`` when no chain exists.

    A CVE with multiple CWEs fans out across mappings, then re-aggregates
    back to one row per CVE with list-valued columns.
    """
    if cves_df.empty:
        return cves_df.copy()

    # CWE -> list of CAPECs
    cwe_to_capecs = (
        capec_cwe_df.groupby("cwe_id")["capec_id"].apply(list).to_dict()
        if not capec_cwe_df.empty else {}
    )
    # CAPEC -> list of ATT&CK IDs
    capec_to_attack = (
        capec_attack_df.groupby("capec_id")["attack_id"].apply(list).to_dict()
        if not capec_attack_df.empty else {}
    )
    # ATT&CK ID -> list of Mitigations
    attack_to_mitig = (
        mitigates_df.groupby("attack_id")["mitigation_id"].apply(list).to_dict()
        if not mitigates_df.empty else {}
    )

    attack_name = (
        dict(zip(techniques_df["attack_id"], techniques_df["name"]))
        if techniques_df is not None and not techniques_df.empty else {}
    )
    mitig_name = (
        dict(zip(mitigations_df["mitigation_id"], mitigations_df["name"]))
        if mitigations_df is not None and not mitigations_df.empty else {}
    )
    bridge = cwe_attack_bridge or {}

    def _uniq(xs: Iterable[str]) -> list[str]:
        out, seen = [], set()
        for x in xs:
            if x not in seen:
                seen.add(x); out.append(x)
        return out

    enriched = []
    for rec in cves_df.to_dict(orient="records"):
        cwes = rec.get("cwe_ids") or ([] if rec.get("cwe_id") is None else [rec["cwe_id"]])
        capecs, attacks, mitigs = [], [], []
        source = "none"
        for cwe in cwes:
            for cap in cwe_to_capecs.get(cwe, []):
                capecs.append(cap)
                for atk in capec_to_attack.get(cap, []):
                    attacks.append(atk)
                    source = "capec"
                    for mit in attack_to_mitig.get(atk, []):
                        mitigs.append(mit)
        # Fallback bridge for CWEs that chain lost signal before ATT&CK
        if not attacks:
            for cwe in cwes:
                for atk in bridge.get(cwe, []):
                    attacks.append(atk)
                    source = "bridge"
                    for mit in attack_to_mitig.get(atk, []):
                        mitigs.append(mit)
        capecs  = _uniq(capecs)
        attacks = _uniq(attacks)
        mitigs  = _uniq(mitigs)
        rec["capec_ids"]        = capecs
        rec["attack_ids"]       = attacks
        rec["mitigation_ids"]   = mitigs
        rec["attack_names"]     = [attack_name.get(a) for a in attacks]
        rec["mitigation_names"] = [mitig_name.get(m) for m in mitigs]
        rec["attack_source"]    = source
        enriched.append(rec)
    return pd.DataFrame(enriched)


# ===========================================================================
# Orchestration
# ===========================================================================
def run_pipeline(
    nvd_filters:        dict,
    capec_xml:          str | os.PathLike | bytes,
    cwe_xml:            str | os.PathLike | bytes | None = None,
    attack_bundle:      str | os.PathLike | dict | None = None,
    *,
    api_key:            str | None = None,
    cache_path:         str = "pipeline_cache.sqlite",
    max_cves:           int | None = None,
    extra_nvd_filters:  list[dict] | None = None,
    cwe_attack_bridge:  dict[str, list[str]] | None = DEFAULT_CWE_ATTACK_BRIDGE,
) -> dict[str, pd.DataFrame]:
    """End-to-end pipeline.

    Parameters
    ----------
    nvd_filters : dict
        Passed to ``NVDClient.iter_cves``. E.g.
        ``{"hasKev": "", "pubStartDate": "2024-01-01T00:00:00.000",
           "pubEndDate":   "2024-01-31T23:59:59.999"}``.
    capec_xml : path or bytes
        Local CAPEC XML (download once from ``CAPEC_XML_URL``).
    cwe_xml : path / bytes / None
        If None, downloaded.
    attack_bundle : path / bytes / dict / None
        If None, downloaded.
    max_cves : int, optional
        Cap applied to each filter set individually (useful in demos).
    extra_nvd_filters : list of dicts, optional
        Additional NVD filter sets for a mixed pull (e.g. non-KEV date-range
        query). Each is fetched separately and deduplicated by cve_id before
        joining. ``max_cves`` applies to each set independently.
    cwe_attack_bridge : dict or None
        Fallback CWE→ATT&CK edges for CWEs with no CAPEC→ATT&CK path.
        Defaults to ``DEFAULT_CWE_ATTACK_BRIDGE``. Pass ``None`` to disable.

    Returns
    -------
    dict with keys:
        ``cves``, ``patterns``, ``capec_cwe``, ``capec_attack``,
        ``techniques``, ``mitigations``, ``mitigates``, ``unified``
    """
    cache = SqliteCache(cache_path)
    client = NVDClient(api_key=api_key, cache=cache)

    def _fetch(filters: dict, cap: int | None) -> list[dict]:
        rows: list[dict] = []
        for v in client.iter_cves(**filters):
            rows.append(v)
            if cap and len(rows) >= cap:
                break
        return rows

    # -- CVE ----------------------------------------------------------------
    raw_cves = _fetch(nvd_filters, max_cves)
    seen_ids: set[str] = {r["cve"]["id"] for r in raw_cves if "cve" in r}

    for extra in (extra_nvd_filters or []):
        for item in _fetch(extra, max_cves):
            cid = item.get("cve", {}).get("id") or item.get("id", "")
            if cid and cid not in seen_ids:
                raw_cves.append(item)
                seen_ids.add(cid)

    log.info("total CVEs after dedup: %d", len(raw_cves))
    cves_df = cves_to_dataframe(raw_cves)

    # -- CAPEC --------------------------------------------------------------
    patterns_df, capec_cwe_df, capec_attack_df = parse_capec(capec_xml)

    # -- CWE ----------------------------------------------------------------
    if cwe_xml is None:
        cwe_bytes = fetch_cwe_xml(cache)
    elif isinstance(cwe_xml, (bytes, bytearray)):
        cwe_bytes = cwe_xml
    else:
        cwe_bytes = Path(cwe_xml).read_bytes()
    cwe_df = parse_cwe(cwe_bytes)

    # -- ATT&CK -------------------------------------------------------------
    if attack_bundle is None:
        bundle = fetch_attack_stix(cache)
    elif isinstance(attack_bundle, dict):
        bundle = attack_bundle
    else:
        bundle = json.loads(Path(attack_bundle).read_text())
    techniques_df, mitigations_df, mitigates_df = parse_attack(bundle)

    # -- Join ---------------------------------------------------------------
    unified = build_unified(
        cves_df, capec_cwe_df, capec_attack_df, mitigates_df,
        mitigations_df=mitigations_df,
        techniques_df=techniques_df,
        cwe_attack_bridge=cwe_attack_bridge,
    )

    cache.close()
    return {
        "cves":          cves_df,
        "cwe":           cwe_df,
        "patterns":      patterns_df,
        "capec_cwe":     capec_cwe_df,
        "capec_attack":  capec_attack_df,
        "techniques":    techniques_df,
        "mitigations":   mitigations_df,
        "mitigates":     mitigates_df,
        "unified":       unified,
    }


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    # Smoke test — against 30-day window ending today. Uncomment & run locally.
    # out = run_pipeline(
    #     nvd_filters={"hasKev": ""},            # just KEV CVEs, small fast set
    #     capec_xml="capec_v3_9.xml",
    #     max_cves=200,
    # )
    # print(out["unified"].head())
