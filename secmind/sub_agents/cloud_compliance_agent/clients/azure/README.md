# Azure Compliance Agent

The Azure Compliance Agent is a sub-agent of the `cloud_compliance_agent` responsible for assessing the security posture of Microsoft Azure environments. It leverages Azure APIs to inventory resources, analyze configurations, and identify security risks.

## 🚀 Features

- **Resource Inventory:** Discovers and lists Azure resources across your subscriptions and resource groups.
- **IAM Analysis:** Provides recommendations for achieving least privilege by analyzing Azure Active Directory (Azure AD) roles, policies, and user permissions.
- **Security Posture Assessment:** Evaluates your Azure environment against common security benchmarks and best practices using Azure Security Center.
- **Vulnerability Detection:** Identifies known vulnerabilities and misconfigurations in your services.

## Examples

### 🛡️ Resource Inventory

- **Description**: Lists all resources within a specified Azure subscription or resource group.
- **Prompt Example**:
  - `"List all virtual machines in my Azure subscription."`

### 🛡️ IAM Recommendations

- **Description**: Analyzes Azure AD roles and generates recommendations to enforce least privilege.
- **Prompt Example**:
  - `"IAM Recommendations for my Azure subscription (Least Privilege)."`
  - `"Analyze the permissions for the user 'user@example.com'."`

### 🛡️ Security Posture

- **Description**: Provides an overall security posture assessment for your Azure subscription, highlighting critical findings from Azure Security Center.
- **Prompt Example**:
  - `"Check overall security posture of my Azure subscription."`
  - `"What are the security recommendations for my Azure subscription?"`
