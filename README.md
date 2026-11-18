# DeploySafe – Intelligent Deployment Risk Analyzer

DeploySafe is a Python-based DevOps security tool that analyzes Dockerfiles and Kubernetes Deployment configurations, identifies security risks, calculates a risk score, and recommends whether a deployment should be allowed, reviewed, or blocked.

It integrates with GitHub Actions to automate security checks during CI.

![DeploySafe CI](https://github.com/uttam9124/DeploySafe/actions/workflows/deploysafe.yml/badge.svg)

## Features

- Dockerfile security analysis
- Kubernetes Deployment configuration analysis
- Risk score from 0–100
- LOW, MEDIUM, HIGH risk classification
- ALLOW, REVIEW, BLOCK deployment decisions
- Hardcoded secret detection
- Root-user detection
- Privileged container detection
- Latest image tag detection
- Missing resource limits and probes detection
- JSON report generation
- Automated testing using pytest
- GitHub Actions CI integration
- Safe and unsafe configuration verification
- Downloadable security reports

## Tech Stack

- Python 3.12
- Docker
- Kubernetes YAML
- pytest
- Git
- GitHub
- GitHub Actions

## Architecture

```text
Developer Push
      |
      v
 GitHub Repository
      |
      v
 GitHub Actions CI
      |
      +--> Install Dependencies
      |
      +--> Run Tests
      |
      +--> Scan Safe Configuration
      |         |
      |         v
      |      LOW RISK
      |       ALLOW
      |
      +--> Scan Unsafe Configuration
                |
                v
             HIGH RISK
              BLOCK
                |
                v
        Upload JSON Reports
## Installation

Clone the repository:

```bash
git clone https://github.com/uttam9124/DeploySafe.git
cd DeploySafe

## Usage

Scan the default configuration:

```bash
python -m analyzer.risk_analyzer
