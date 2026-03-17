# GCP Compliance Agent

The GCP Compliance Agent is a sub-agent of the `cloud_compliance_agent` responsible for assessing the security posture of Google Cloud Platform (GCP) environments. It leverages GCP APIs to inventory resources, analyze configurations, and identify security risks.

## 🚀 Features

- **Resource Inventory:** Discovers and lists GCP resources across your projects.
- **IAM Analysis:** Provides recommendations for achieving least privilege by analyzing IAM roles, policies, and user permissions.
- **Security Posture Assessment:** Evaluates your GCP environment against common security benchmarks and best practices using the Security Command Center API.
- **Vulnerability Detection:** Identifies known vulnerabilities and misconfigurations in your services.

## Examples

### 🛡️ Resource Inventory

- **Description**: Lists all resources within a specified GCP project.
- **Prompt Example**:
  - `"List all Compute Engine instances in my project 'my-gcp-project'."`

### 🛡️ IAM Recommendations

- **Description**: Analyzes IAM policies and generates recommendations to enforce least privilege.
- **Prompt Example**:
  - `"IAM Recommendations for my GCP project (Least Privilege)."`
  - `"Analyze the permissions for the service account 'my-service-account@my-gcp-project.iam.gserviceaccount.com'."`

### 🛡️ Security Posture

- **Description**: Provides an overall security posture assessment for your GCP project, highlighting critical findings from the Security Command Center.
- **Prompt Example**:
  - `"Check overall security posture of GCP project my-gcp-project."`
  - `"What are the active findings in the Security Command Center for my project?"`
