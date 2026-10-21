# AI-Powered Cybersecurity Defense

**CIS 490 | Computer Information Systems – Cybersecurity Emphasis**  
**Connor Bates | Colorado State University Pueblo**

## Project Overview

This project explores the application of artificial intelligence (AI) and machine learning to cybersecurity vulnerability analysis, threat identification, and defensive decision support.

Developed as part of CIS 490 at Colorado State University Pueblo, the project uses Python to analyze cybersecurity vulnerabilities and predict relevant defensive mitigations.

The system combines vulnerability descriptions, severity information, and cybersecurity framework mappings to generate mitigation recommendations using six machine learning approaches.

The project incorporates information associated with CVE, CVSS, CWE, CAPEC, and MITRE ATT&CK.

## Project Objectives

- Analyze cybersecurity vulnerabilities using machine learning.
- Prepare and process large cybersecurity datasets.
- Examine vulnerability descriptions, severity scores, and weakness classifications.
- Apply MITRE ATT&CK mitigation mappings.
- Train and evaluate multiple machine learning models.
- Compare model performance using classification metrics.
- Generate defensive mitigation recommendations based on vulnerability characteristics.
- Explore how AI can support cybersecurity decision-making.

## Machine Learning Models

The project evaluates six machine learning approaches.

### 1. Baseline Model

Establishes a reference point for evaluating the performance of more advanced machine learning models.

### 2. Logistic Regression

Uses supervised classification to predict mitigation labels from vulnerability-related features.

### 3. Random Forest

Uses an ensemble of decision trees to identify patterns and predict appropriate cybersecurity mitigations.

### 4. Linear Support Vector Machine (SVM)

Uses a linear classification approach to predict mitigation labels based on processed vulnerability information.

### 5. Naive Bayes

Applies probabilistic classification to vulnerability-related features.

### 6. Gradient Boosting

Uses sequential ensemble learning to improve mitigation prediction.

These approaches are evaluated to compare their effectiveness in predicting cybersecurity mitigations.

## Cybersecurity Frameworks and Data Sources

The project uses unified vulnerability datasets containing information associated with several established cybersecurity frameworks.

### Common Vulnerabilities and Exposures (CVE)

CVE provides standardized identifiers for publicly disclosed cybersecurity vulnerabilities.

### Common Vulnerability Scoring System (CVSS)

CVSS provides numerical severity scores used to help assess vulnerabilities.

### Common Weakness Enumeration (CWE)

CWE categorizes software and hardware weaknesses that can contribute to cybersecurity vulnerabilities.

### Common Attack Pattern Enumeration and Classification (CAPEC)

CAPEC documents common attack patterns and their relationships to underlying security weaknesses.

### MITRE ATT&CK

MITRE ATT&CK provides a knowledge base of adversary tactics, techniques, and defensive mitigations.

The project uses MITRE ATT&CK mappings contained in the prepared CVE datasets to support mitigation predictions.

The final machine learning notebook does not directly load the original Enterprise ATT&CK or ICS ATT&CK JSON files. Instead, it uses the prepared unified datasets.

### Official Data Sources

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Enterprise ATT&CK](https://attack.mitre.org/matrices/enterprise/)
- [ICS ATT&CK](https://attack.mitre.org/matrices/ics/)
- [National Vulnerability Database](https://nvd.nist.gov/)
- [Common Vulnerabilities and Exposures](https://www.cve.org/)
- [Common Weakness Enumeration](https://cwe.mitre.org/)
- [CAPEC](https://capec.mitre.org/)

## Technologies Used

- Python
- Google Colab
- Jupyter Notebook
- pandas
- NumPy
- scikit-learn
- Matplotlib
- TF-IDF Vectorization
- Natural Language Processing
- Multi-label Classification
- Machine Learning
- Cybersecurity Vulnerability Analysis
- MITRE ATT&CK Framework

## Repository Contents

| File | Description |
|---|---|
| `CIS490_Cyber_Defense_Project.ipynb` | Main Jupyter Notebook containing machine learning models, evaluation, and mitigation recommendations |
| `data_pipeline.ipynb` | Supporting data preparation notebook |
| `requirements.txt` | Python dependencies required for the project |
| `README.md` | Project documentation |

The large training and testing datasets are distributed separately through GitHub Releases.

## Required Datasets

The project uses two unified CVE datasets.

| Dataset | Purpose | Approximate Size |
|---|---|---|
| `cve_unified_100k.csv` | Primary training dataset | 121.48 MB |
| `cve_unified_100k_2025-2026.csv` | Additional testing and evaluation dataset | 82.01 MB |

These datasets contain vulnerability-related information and cybersecurity mappings used by the machine learning models.

### Download the Datasets

Both datasets are provided through the project's GitHub Release.

**[Download AI Cybersecurity Defense Datasets — v1.0.0](https://github.com/ConnorBatesCyber/AI-Cybersecurity-Defense/releases/tag/v1.0.0)**

Individual dataset downloads:

- [Download Training Dataset — cve_unified_100k.csv](https://github.com/ConnorBatesCyber/AI-Cybersecurity-Defense/releases/download/v1.0.0/cve_unified_100k.csv)
- [Download Testing Dataset — cve_unified_100k_2025-2026.csv](https://github.com/ConnorBatesCyber/AI-Cybersecurity-Defense/releases/download/v1.0.0/cve_unified_100k_2025-2026.csv)

These datasets are distributed separately because they exceed GitHub's standard browser-upload limit.

The unified datasets contain prepared vulnerability information and mappings. Downloading the original NVD or MITRE ATT&CK datasets alone does not reproduce these prepared CSV files.

## How to Run the Project

### Step 1 — Download the Repository

Download the project from GitHub:

[AI Cybersecurity Defense Repository](https://github.com/ConnorBatesCyber/AI-Cybersecurity-Defense)

Select **Code → Download ZIP**, or clone the repository using Git.

### Step 2 — Open Google Colab

Visit [Google Colab](https://colab.research.google.com/).

Open the following notebook:

`CIS490_Cyber_Defense_Project.ipynb`

### Step 3 — Install Dependencies

Install the required Python packages using the provided `requirements.txt` file, or follow the notebook's dependency instructions.

The project uses Python libraries including pandas, NumPy, scikit-learn, and Matplotlib.

### Step 4 — Download the Datasets

Download both CSV files from the [v1.0.0 dataset release](https://github.com/ConnorBatesCyber/AI-Cybersecurity-Defense/releases/tag/v1.0.0).

Required filenames:

- `cve_unified_100k.csv`
- `cve_unified_100k_2025-2026.csv`

### Step 5 — Upload the Datasets to Google Colab

Upload both CSV files into the Google Colab session.

The notebook expects the following file locations:

`/content/cve_unified_100k.csv`

`/content/cve_unified_100k_2025-2026.csv`

Ensure that both files have the correct names before running the notebook.

### Step 6 — Execute the Notebook

Run the notebook cells in order.

The notebook performs:

1. Dataset loading and validation.
2. Data cleaning and preprocessing.
3. Feature extraction and engineering.
4. Machine learning model training.
5. Model evaluation and comparison.
6. Cybersecurity mitigation prediction.
7. Result generation and export.

Some model training operations may require substantial memory and processing time.

## Data Preprocessing and Feature Engineering

The project prepares vulnerability data for machine learning through several preprocessing steps.

These include:

- Handling missing values.
- Processing vulnerability descriptions.
- Preparing numerical severity features.
- Encoding categorical cybersecurity information.
- Converting text into numerical representations using TF-IDF.
- Preparing multi-label mitigation targets.

The models use vulnerability-related information to learn relationships between vulnerability characteristics and defensive mitigations.

## Model Evaluation

The project compares model performance using several evaluation measures.

### Micro F1-Score

Measures classification performance across mitigation predictions by aggregating contributions from all labels.

### Macro F1-Score

Calculates classification performance across individual labels, giving each label equal weight.

### Top-K Evaluation

Examines whether relevant mitigation labels appear among the highest-ranked predictions.

The notebook includes Top-3 and Top-5 comparison metrics where available.

### Model Comparison

The project generates comparison results to evaluate the effectiveness of the different machine learning approaches.

The evaluation process helps identify strengths, weaknesses, and differences between the models.

## Cybersecurity Mitigation Recommendations

A primary objective of the project is to generate practical defensive recommendations from vulnerability information.

The system uses machine learning predictions to identify relevant MITRE ATT&CK mitigation labels.

These predictions can then be translated into human-readable cybersecurity recommendations.

The resulting information can assist with:

- Vulnerability analysis.
- Defensive planning.
- Security decision support.
- Prioritization of potential mitigation strategies.
- Understanding relationships between vulnerabilities and defensive controls.

The system is intended as a decision-support tool and does not replace professional cybersecurity analysis or validation.

## Generated Project Results

The notebook includes functionality to export model evaluations and prediction results.

| Output File | Description |
|---|---|
| `model_results.csv` | Machine learning performance metrics |
| `model_results.json` | Model evaluation results in JSON format |
| `model_comparison.csv` | Comparison of the evaluated models |
| `final_predictions.csv` | Generated mitigation prediction results |

These files can be generated by executing the notebook with the required datasets.

## Project Limitations

The project has several limitations:

- Model accuracy depends on the quality and completeness of the vulnerability datasets.
- Some mitigation labels may be more common than others, creating class imbalance.
- Historical cybersecurity mappings may not represent newly emerging threats.
- Machine learning predictions may not reflect organization-specific security requirements.
- Large datasets can require substantial processing time and memory.
- The prepared datasets are required to reproduce the machine learning workflow.

These limitations highlight the importance of combining AI-generated recommendations with professional cybersecurity judgment.

## Future Improvements

Potential future enhancements include:

- Expanding the vulnerability datasets with newer CVE records.
- Improving predictions for less common mitigation labels.
- Incorporating additional threat intelligence sources.
- Developing a graphical user interface or web application.
- Automating cybersecurity dataset updates.
- Comparing additional machine learning algorithms.
- Improving model explainability.
- Evaluating recommendations against independent cybersecurity datasets.

## Skills Demonstrated

This project demonstrates experience with:

- Python programming
- Artificial intelligence and machine learning
- Cybersecurity vulnerability analysis
- Data preprocessing and feature engineering
- Natural language processing
- Multi-label classification
- Model training and evaluation
- Cybersecurity framework integration
- Jupyter Notebook development
- Data analysis and technical documentation

## Author

**Connor Bates**  
Computer Information Systems — Cybersecurity Emphasis  
Colorado State University Pueblo

**GitHub:** [ConnorBatesCyber](https://github.com/ConnorBatesCyber)

**Project Repository:** [AI-Cybersecurity-Defense](https://github.com/ConnorBatesCyber/AI-Cybersecurity-Defense)

---

*Developed as an academic project for CIS 490 at Colorado State University Pueblo.*
