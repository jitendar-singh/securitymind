# Suggested Features for gcp_workload_security_agent

Here are the features that would make the `gcp_workload_security_agent` significantly more powerful, categorized by security domain.

## 1. Deeper Asset Discovery and Analysis

The agent should be able to create a complete and detailed inventory of all cloud resources, not just GCE instances. This provides a full view of the potential attack surface.

- [x] **Feature:** **Comprehensive Resource Listing.**
    - **Description:** Expand listing capabilities to include other critical GCP services like GKE clusters, Cloud Run services, Cloud Functions, VPC Firewall Rules, and IAM policies.
    - **Example Prompts:**
        - `list gke clusters for project my-prod-project`
        - `show firewall rules for network default`
        - `get iam policy for project my-prod-project`

- [x] **Feature:** **Detailed Resource Metadata.**
    - **Description:** Instead of just returning names, return rich metadata. For a VM, this would include its service account, network interfaces (with public IPs), assigned labels, and applicable firewall rules. This context is crucial for security analysis.
    - **Note:** The agent now returns the service account, network interfaces (with public IPs), assigned labels, and applicable firewall rules for a GCE instance.
    - **Example Prompt:**
        - `get details for gce instance web-server-1 in zone us-central1-a`

- [x] **Feature:** **Firewall Rule Analysis.**
    - **Description:** Analyze firewall rules for common misconfigurations like allowing unrestricted access to sensitive ports (e.g., SSH, RDP) from the internet.
    - **Note:** A basic implementation of this feature has been added, which checks for unrestricted access to a predefined list of sensitive ports.
    - **Example Prompt:**
        - `analyze firewall rules for project my-prod-project`

## 2. Expanded Security and Configuration Auditing

Move beyond just CVEs in containers and assess the configuration of the infrastructure itself against security best practices.

- [ ] **Feature:** **CIS Benchmark Auditing.**
    - **Description:** Scan the configuration of GCP resources against the industry-standard CIS (Center for Internet Security) Benchmarks. This is a common requirement for compliance.
    - **Example Prompts:**
        - `audit gke cluster my-cluster against cis benchmark`
        - `check project my-prod-project for cis compliance gaps`

- [x] **Feature:** **IAM Policy Analysis.**
    - **Description:** Provide a query interface to understand complex permissions, which are often a source of security breaches. A basic implementation of this feature has been added, which checks for overly permissive roles.
    - **Example Prompts:**
        - `analyze iam policy for project my-prod-project`
        - `who can act as serviceAccount my-sa@my-project.iam.gserviceaccount.com?`
        - `list all users with owner role in project my-prod-project`
        - `are there any publicly accessible BigQuery datasets?`

## 3. Proactive and Runtime Security

Integrate with real-time security signals and add the ability to take action, moving the agent from a passive scanner to an active defender.

- [ ] **Feature:** **Security Command Center (SCC) Integration.**
    - **Description:** Tap into GCP's native security monitoring to report on and process findings.
    - **Example Prompts:**
        - `list new critical findings from security command center for the last 24 hours`
        - `get details for scc finding <finding_id>`

- [ ] **Feature:** **Automated Remediation Actions (with caution).**
    - **Description:** Allow the agent to take corrective actions. This is a very powerful feature that should be used carefully, perhaps first in a "dry run" mode that only suggests the action.
    - **Example Prompts:**
        - `revoke public ip from gce instance temp-dev-vm`
        - `apply firewall rule quarantine-ssh to gce instance compromised-vm`
        - `suggest a more restrictive iam policy for serviceAccount overly-permissive-sa`

## 4. Enhanced Vulnerability Management

Improve the existing scanning capabilities to cover more of the environment.

- [ ] **Feature:** **GCE Instance (OS) Vulnerability Scanning.**
    - **Description:** The current agent only scans containers. A major enhancement would be to scan the operating systems of the GCE VMs themselves for vulnerabilities, likely by integrating with GCP's built-in **VM Manager**.
    - **Example Prompt:**
        - `scan gce instance web-server-1 for os vulnerabilities`
