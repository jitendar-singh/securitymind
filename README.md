
# secmind

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![Security](https://img.shields.io/badge/security-monitored-important)

**secmind** is the master security agent responsible for orchestrating and delegating various security-related tasks to specialized sub-agents. It acts as a central hub for security operations, ensuring that user requests are routed to the most appropriate agent for resolution.

## 🚀 Capabilities

- **Task Delegation**: Directs security queries and tasks to specialized agents.
- **Security Orchestration**: Manages the flow of security-related operations across agents.

## 🧠 Delegated Agents

### 🔍 vuln_triage_agent
- **Description**: Triages vulnerabilities and checks licenses for various ecosystems.
- **Prompt Examples**:
  - `"What is the license for the @azure/identity npm package?"`
  - `"Can you triage this vulnerability for me: CVE-2023-XXXX affecting our production server?"`

### 🛡️ code_review_agent
- **Description**: Reviews code and delegates to Jira for issue creation if findings are identified.
- **Prompt Examples**:
  - `"Please review the security of the code in this pull request: https://github.com/org/repo/pull/123"`
  - `"Perform a static code analysis on the latest commit in the main branch."`

### 📋 jira_agent
- **Description**: Creates Jira issues from security findings or general requests.
- **Prompt Examples**:
  - `"Create a Jira ticket to track the critical SQL injection vulnerability found in the user authentication module."`
  - `"I need a Jira issue for the new feature request 'Implement Two-Factor Authentication'."`

### 📚 policy_agent
- **Description**: Reads policies from local files or Confluence.
- **Prompt Examples**:
  - `"What are the key points from our open-source software license policy?"`
  - `"List all the available policy documents."`

## 🧑‍💻 How to Use

Simply pose your security-related question or task to **secmind**. It will automatically analyze your request and transfer it to the most suitable specialized agent to provide an accurate and efficient response. You do not need to explicitly mention the sub-agent names.

## 🛠️ Tools

**secmind** uses the following tool to manage its delegation:
```python
transfer_to_agent(agent_name: str)
```
Hands off control to another agent when it's more suitable to answer the user's question according to the agent's description.

## 📦 Setup Instructions

1. Clone the repository:
   ```bash
   git clone https://github.com/jitendar-singh/securitymind.git
   cd secmind
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the application:
   ```bash
   adk web
   ```

## 📘 Usage Examples

```python
# Example 1: Ask about a vulnerability
response = secmind.handle_request("Can you triage CVE-2023-XXXX?")

# Example 2: Request a code review
response = secmind.handle_request("Review the security of this pull request: https://github.com/org/repo/pull/123")

# Example 3: Create a Jira issue
response = secmind.handle_request("Create a Jira ticket for the SQL injection vulnerability.")
```

---

Feel free to contribute or raise issues to improve secmind!
