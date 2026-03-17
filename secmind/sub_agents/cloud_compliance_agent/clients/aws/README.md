# AWS Compliance Agent

The AWS Compliance Agent is a sub-agent of the `cloud_compliance_agent` responsible for assessing the security posture of Amazon Web Services (AWS) environments. It leverages AWS APIs to inventory resources, analyze configurations, and identify security risks.

## 🚀 Features

- **Resource Inventory:** Discovers and lists AWS resources across your accounts.
- **IAM Analysis:** Provides recommendations for achieving least privilege by analyzing IAM roles, policies, and user permissions. It integrates with AWS IAM Access Analyzer for this purpose.
- **Security Posture Assessment:** Evaluates your AWS environment against common security benchmarks and best practices.
- **Vulnerability Detection:** Identifies known vulnerabilities and misconfigurations in your services.

## Examples

### 🛡️ Resource Inventory

- **Description**: Lists all resources within a specified AWS region or account.
- **Prompt Example**:
  - `"List all S3 buckets in my default AWS account."`

### 🛡️ IAM Recommendations

- **Description**: Analyzes IAM policies and generates recommendations to enforce least privilege.
- **Prompt Example**:
  - `"IAM Recommendations for my AWS account (Least Privilege)."`
  - `"Analyze the permissions for the IAM role 'ecs-task-role'."`

### 🛡️ Security Posture

- **Description**: Provides an overall security posture assessment for your AWS account, highlighting critical findings.
- **Prompt Example**:
  - `"Check overall security posture of my AWS account."`
  - `"What are the top 5 security risks in my AWS environment?"`
