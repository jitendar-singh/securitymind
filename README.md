# Security Mind: AI-Powered Application Security Posture Management (ASPM) Platform

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/jitendar-singh/securitymind/actions)
[![Security](https://img.shields.io/badge/security-active-green.svg)](https://github.com/jitendar-singh/securitymind/security)

Security Mind is an innovative, multi-agent AI system designed to enhance application security posture management (ASPM). Built on advanced AI architectures, it leverages collaborative agents to automate security workflows, identify risks, ensure compliance, and support DevSecOps practices. Whether you’re triaging vulnerabilities, reviewing code, or generating reports, Security Mind provides intelligent, actionable insights to secure your applications throughout the software development lifecycle.

## Key highlights:

- **Multi-Agent Architecture:** Specialized agents (e.g., compliance, threat detection, remediation) work together for complex tasks.
- **Integration-Friendly:** Supports tools like Jira, GitHub, and cloud APIs (e.g., GCP, AWS).
- **AI-Powered:** Utilizes LLMs for natural language queries, threat modeling, and policy interpretation.
- **Focus Areas:** Vulnerability management, license compliance, code reviews, and more.

Security Mind is ideal for security engineers, developers, and compliance teams aiming to reduce risk exposure and accelerate secure development.

## 🚀 Features

- **Security Posture Reporting:** Generate comprehensive reports on project security, including access management, vulnerabilities, and compliance gaps.
- **CVE Triage:** Analyze CVEs for severity, impact, affected versions, and mitigation strategies.
- **License Compliance Checks:** Review open-source packages for license types (e.g., MIT, GPL) and policy adherence.
- **Policy Interpretation:** Query security policies for details like copyleft licenses or SLAs in vulnerability management.
- **Code/PR Reviews:** Scan pull requests for security issues, best practices, and vulnerabilities.
- **Ticket Creation:** Automate Jira (or similar) ticket generation for issues and remediations.
- **Threat Modeling:** Perform structured threat assessments using frameworks like STRIDE.
- **Cloud Resource Scanning:** List and audit resources (e.g., in GCP) for security misconfigurations.
- **Extensible:** Easily add custom agents or tools for specific use cases.

## Examples

### 🛡️ Triage a CVE

- **Description**: Triages vulnerabilities using NVD API and checks licenses across ecosystems (pypi, npm, maven, etc.) with auto-detection and web search fallbacks.
- **Prompt Examples**:
  - `"What is the license for the @azure/identity package?"` (auto-detects npm)
  - `"Triage this vulnerability: CVE-2023-4863 affecting our web server."`
  - `"Analyze this SBOM: [SBOM JSON content]"`

### 🛡️ code_review_agent

- **Description**: Performs AI-driven code reviews using Gemini, focusing on code smells, security, readability, and best practices. Supports auto-language detection and GitHub PR diffs.
- **Prompt Examples**:
  - `"Review this code: def add(a, b): return a + b"`
  - `"Review the security of this pull request: https://github.com/org/repo/pull/123"`

### 📋 jira_agent

- **Description**: Creates Jira issues from findings or requests, integrated via Atlassian API.
- **Prompt Examples**:
  - `"Create a Jira ticket for the SQL injection vulnerability in auth module."`
  - `"Track new feature: Implement MFA."`

### 📚 policy_agent

- **Description**: Reads and summarizes policies from local files (txt, pdf, docx) or Confluence.
- **Prompt Examples**:
  - `"Summarize our open-source license policy."`
  - `"List available policies."`

### ☁️ cloud_compliance_agent

- **Description**: Inventories GCP resources and assesses security posture using Cloud Asset Inventory and Security Command Center APIs. Supports overall posture summaries with findings by severity.
- **Prompt Examples**:
  - `"Check resources in project my-project-id"`
  - `"IAM Recommendations for (Least Privilege)"`
  - `"Identified service account access keys older than the recommended 90 days."`
  - `"Check overall security posture of GCP project my-project-id"`

### 🔒 app_sec_review_agent

- **Description**: Conducts threat modeling for applications, gathering details on framework, networking, deployment, and cloud env, then generates a sectioned report with recommendations using STRIDE model.
- **Prompt Examples**:
  - `"Perform threat modeling for my web app using Django on AWS."`
  - `"App sec review: Framework - React/Node, Deployment - GCP Kubernetes."`

## 🧑‍💻 How to Use

Interact with SecurityMind by posing natural language queries. It delegates automatically—no need to specify sub-agents. For advanced use, upload SBOMs or provide code snippets/PR URLs.

## 🛠️ Tools

SecurityMind uses these tools for delegation and execution:

- `transfer_to_agent(agent_name: str)`: Hands off to another agent.
- Sub-agent specific tools (e.g., `review_code`, `triage_vulnerability`, `parse_sbom`—see code for details).

## 📦 Setup Instructions

1. Clone the repository:
   
   ```
   git clone https://github.com/jitendar-singh/securitymind.git
   cd securitymind
   ```
2. Install dependencies:
   
   ```
   pip install -r requirements.txt
   ```
3. Set environment variables in `.env`:
- `GOOGLE_API_KEY`: For Gemini models.
- `NVD_API_KEY`: For vulnerability triage (get from https://nvd.nist.gov/developers/request-an-api-key).
- `JIRA_URL`, `JIRA_USER`, `JIRA_TOKEN`: For Jira integration.
- Optional: `CONFLUENCE_URL`, etc., for policy agent.
- `GOOGLE_APPLICATION_CREDENTIALS`: Path to GCP service account key for cloud compliance.
- `GOOGLE_CLOUD_PROJECT`: Default GCP project ID.
4. Run the application:
   
   ```
   adk web
   ```

## 📘 Usage Examples

```python
# Vulnerability triage
response = secmind.handle_request("Triage CVE-2023-4863")

# License check with auto-detection
response = secmind.handle_request("License for numpy")

# Code review
response = secmind.handle_request("Review: print('Hello')")

# SBOM analysis
sbom_json = '{"bomFormat": "CycloneDX", "components": [{"purl": "pkg:npm/@azure/identity"}]}'
response = secmind.handle_request(f"Analyze SBOM: {sbom_json}")

# Jira creation
response = secmind.handle_request("Create Jira for high severity vuln")

# Cloud compliance
response = secmind.handle_request("Check overall security posture for projects/my-project-id")

# App sec review
response = secmind.handle_request("App sec review: Framework - .NET, Deployment - GCP")
```

## Workflow

![secmind-workflow](https://github.com/user-attachments/assets/40c17280-4b1d-4425-8778-ea9f5769c292)

## FAQ
**Q: Does SecMind require internet access?**
- `"Yes, for API integrations and real-time data; offline mode available for local scans."`

**Q: Is it secure?**
- `"Yes, uses encrypted connections; no user data stored."`

**Q: Supported clouds?**
- `"GCP (primary), AWS, Azure (beta)."`

**Q: How to extend?**
- `"Add agents via Python classes; see docs."`


## Roadmap
- **v1.0:** Core features (current).
- **v1.1:** AWS/Azure full support, UI dashboard.
- **v1.2:** ML-based anomaly detection.
- **v2.0:** Enterprise integrations (e.g., Splunk, SIEM).
Track progress on GitHub Issues.


## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](https://github.com/jitendar-singh/securitymind/blob/main/CONTRIBUTING.md) for guidelines. For issues, use GitHub Issues.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/jitendar-singh/securitymind/blob/main/LICENSE) file for details.

## About

Built by [Jitendar Singh](https://github.com/jitendar-singh). For SaaS hosting or custom integrations, contact via GitHub.
