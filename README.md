# SecurityMind

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/jitendar-singh/securitymind/actions)
[![Security](https://img.shields.io/badge/security-active-green.svg)](https://github.com/jitendar-singh/securitymind/security)

SecurityMind is an AI-powered security agent built using Google’s Agent Development Kit (ADK). It acts as a central orchestrator for security operations, delegating tasks to specialized sub-agents for efficient handling of vulnerabilities, code reviews, policies, and more.

## 🚀 Capabilities

- **Task Delegation**: Routes security queries to appropriate sub-agents.
- **Security Orchestration**: Manages workflows across vulnerability triage, code reviews, Jira issue creation, and policy retrieval.
- **Auto-Detection**: Automatically detects package ecosystems for license checks and parses SBOM files for bulk analysis.

## 🧠 Delegated Agents

### 🔍 vuln_triage_agent

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
```

## 🤝 Contributing

Contributions welcome! See <CONTRIBUTING.md> for guidelines. For issues, use GitHub Issues.

## 📄 License

This project is licensed under the MIT License - see the <LICENSE> file for details.

## About

Built by [Jitendar Singh](https://github.com/jitendar-singh). For SaaS hosting or custom integrations, contact via GitHub.