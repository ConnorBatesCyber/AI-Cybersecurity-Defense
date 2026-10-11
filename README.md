# AI-Powered Cybersecurity Defense
### CIS 490 | Computer Information Systems – Cybersecurity Emphasis
**Connor Bates | Colorado State University Pueblo**

## Project Overview

This project explores the application of artificial intelligence (AI) and machine learning to cybersecurity defense, vulnerability analysis, and security decision support.

Developed as part of CIS 490 at Colorado State University Pueblo, the project investigates how machine learning algorithms can analyze cybersecurity datasets, identify patterns, classify security-related information, and support decisions about potential threats and vulnerabilities.

The project combines Python programming, data preprocessing, machine learning, model evaluation, and established cybersecurity frameworks.

## Project Objectives

- Develop and evaluate multiple machine learning approaches for cybersecurity applications.
- Process and analyze vulnerability information from publicly available cybersecurity datasets.
- Investigate relationships between vulnerability characteristics and security classifications.
- Compare machine learning algorithms using appropriate evaluation metrics.
- Explore the use of MITRE ATT&CK information to support cybersecurity analysis.
- Demonstrate how AI can assist security professionals in analyzing large volumes of information.

## Machine Learning Models

The project explores five machine learning model families and a frequency-based baseline:

| Model | Purpose |
|---|---|
| Logistic Regression | Establish a statistical classification approach |
| Random Forest | Identify complex patterns using an ensemble of decision trees |
| Linear Support Vector Machine | Perform classification using linear decision boundaries |
| Naive Bayes | Evaluate a probabilistic classification approach |
| Gradient Boosting | Explore sequential ensemble learning |
| Frequency-Based Baseline | Provide a reference point for evaluating model performance |

These approaches are compared to investigate their suitability for the project's classification and security analysis tasks.

## Cybersecurity Data Sources

The project uses or explores publicly available cybersecurity information, including:

**National Vulnerability Database (NVD)**
- Common Vulnerabilities and Exposures (CVE) records
- CVSS vulnerability severity information
- Vulnerability descriptions and classifications

**MITRE ATT&CK**
- Enterprise ATT&CK
- Mobile ATT&CK
- Industrial Control Systems (ICS) ATT&CK
- Adversarial tactics, techniques, and mitigation information

These resources provide a foundation for investigating cybersecurity threats, vulnerability characteristics, and defensive decision-making.

## Technologies and Skills

**Programming and Data Science**
- Python
- Jupyter Notebook
- Data preprocessing and transformation
- Machine learning
- Classification algorithms
- Model evaluation
- Data analysis

**Cybersecurity**
- Vulnerability analysis
- CVE and CVSS data
- MITRE ATT&CK framework
- Threat analysis
- Cybersecurity decision support
- Security-related data classification

## Project Methodology

### 1. Data Collection

Gathered cybersecurity-related information from vulnerability datasets and security frameworks.

### 2. Data Preparation

Prepared datasets for analysis through cleaning, transformation, and feature processing.

### 3. Model Development

Implemented multiple machine learning approaches to investigate cybersecurity-related classification tasks.

### 4. Model Evaluation

Compared model performance using classification metrics and baseline results.

### 5. Security Analysis

Explored how the resulting predictions and cybersecurity information could contribute to vulnerability analysis and defensive recommendations.

## Results and Evaluation

The project demonstrates how multiple machine learning methods can be applied to structured cybersecurity information.

Model evaluation includes classification performance comparisons and analysis of how different approaches behave on the selected datasets.

The notebook contains experimental results, including high reported classification scores in certain evaluations. These results should be interpreted in the context of the particular datasets, target labels, and experimental methodology.

**Important limitation:** The project is an academic proof of concept. Its experimental results do not establish production-ready threat detection, real-world attack prevention, or independently validated operational performance.

## Repository Contents

- `CIS490_Cyber_Defense_Project.ipynb` — Jupyter notebook containing Python code and machine learning workflows.
- `README.md` — Project overview and technical documentation.
- `requirements.txt` — Python dependencies, when added.

Additional project datasets and supporting materials may be required to reproduce individual notebook workflows.

## Running the Project

1. Download or clone the repository.
2. Install Python and Jupyter Notebook.
3. Install the required Python libraries.
4. Obtain the necessary datasets from their authorized sources.
5. Update any local dataset paths in the notebook.
6. Open the notebook in Jupyter and run the applicable cells in sequence.

Some sections may require additional configuration, dataset preparation, or troubleshooting.

## Skills Demonstrated

- Python programming
- Machine learning model development
- Cybersecurity data analysis
- Vulnerability assessment concepts
- Data preprocessing
- Algorithm comparison
- Technical documentation
- Analytical problem-solving

## Future Improvements

Potential improvements include:

- Testing models against additional cybersecurity datasets.
- Improving feature engineering and dataset validation.
- Expanding model evaluation and cross-validation.
- Investigating class imbalance and potential data leakage.
- Developing more interpretable model outputs.
- Exploring integration with cybersecurity monitoring workflows.
- Improving reproducibility and automation.

## About the Developer

**Connor Bates**

Computer Information Systems student with a Cybersecurity emphasis at Colorado State University Pueblo and U.S. Navy veteran.

My professional interests include cybersecurity, digital forensics, artificial intelligence, machine learning, and information technology.

**LinkedIn:** https://www.linkedin.com/in/connor-bates-8457a5194/

---

*This repository documents an academic cybersecurity and machine learning project. It is intended for educational, research, and professional portfolio purposes.*
