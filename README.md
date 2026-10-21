# AI-Powered Cybersecurity Defense

**CIS 490 | Computer Information Systems – Cybersecurity Emphasis**  
**Connor Bates | Colorado State University Pueblo**

## Project Overview

This project explores the application of artificial intelligence (AI) and machine learning to cybersecurity vulnerability analysis and defensive decision support.

Developed as part of CIS 490 at Colorado State University Pueblo, the project uses Python and machine learning to analyze Common Vulnerabilities and Exposures (CVEs), evaluate vulnerability characteristics, and predict relevant cybersecurity mitigation strategies.

The system combines vulnerability descriptions, severity information, and mappings to established cybersecurity frameworks to generate human-readable defense recommendations.

## Project Objectives

- Analyze cybersecurity vulnerability data using Python.
- Prepare and clean datasets for machine learning.
- Examine CVE severity and associated cybersecurity weaknesses.
- Apply MITRE ATT&CK mitigation mappings.
- Train and evaluate multiple machine learning approaches.
- Compare model performance using classification metrics.
- Generate cybersecurity mitigation recommendations for vulnerabilities.

## Machine Learning Models

The project evaluates six approaches:

1. **Logistic Regression** — Predicts mitigation labels using vulnerability-related features.
2. **Random Forest** — Uses an ensemble of decision trees for classification.
3. **Linear Support Vector Machine (SVM)** — Classifies mitigation labels using a linear decision boundary.
4. **Naive Bayes** — Applies probabilistic classification techniques.
5. **Gradient Boosting** — Uses sequential ensemble learning to predict mitigations.
6. **Baseline Model** — Provides a reference for comparing machine learning performance.

Model evaluation includes multi-label classification metrics such as micro and macro F1-scores, along with comparisons of mitigation prediction performance.

## Cybersecurity Frameworks and Data Sources

The project uses unified vulnerability datasets containing information derived from established cybersecurity resources.

**CVE — Common Vulnerabilities and Exposures**

Identifies publicly disclosed cybersecurity vulnerabilities.

**CVSS — Common Vulnerability Scoring System**

Provides severity information used to characterize vulnerabilities.

**CWE
