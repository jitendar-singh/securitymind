# Required Permissions

Security Mind is designed to operate with the principle of least privilege. The application only requires read-only access to your cloud environment to perform its security assessments. It does not perform any write operations or configuration changes.

This document outlines the minimum required IAM permissions for each supported cloud provider.

## Google Cloud Platform (GCP)

We recommend creating a custom IAM role with the exact permissions needed to run the compliance checks.

### Required Permissions

The following permissions are required for the GCP service account used by Security Mind:

**Cloud Compliance Agent (existing):**

*   `cloudasset.assets.list` - To list cloud resources.
*   `containeranalysis.occurrences.list` - To list vulnerability occurrences for container images.
*   `compute.instances.list` - To list GCE instances.
*   `iam.serviceAccountKeys.list` - To list service account keys.
*   `orgpolicy.policy.get` - To get organization policies.
*   `recommender.iamPolicyRecommendations.list` - To list IAM recommendations.
*   `securitycenter.findings.list` - To list security findings.
*   `securitycenter.sources.list` - To list security sources.

**GCP Workload Security Agent:**

*   `compute.firewalls.list` - To list VPC firewall rules.
*   `compute.zones.list` - For aggregated GCE listing.
*   `container.clusters.list` - To list GKE clusters.
*   `run.services.list` - To list Cloud Run services.
*   `cloudfunctions.functions.list` - To list Cloud Functions.
*   `resourcemanager.projects.getIamPolicy` - To read project IAM (privilege escalation analysis).

**Network & Data-Security Checks (M2):**

*   `compute.subnetworks.list` - To check VPC flow log status per subnet.
*   `compute.networks.get` - To detect the legacy default VPC.
*   `compute.securityPolicies.list` - To enumerate Cloud Armor policies.
*   `compute.backendServices.list` - To check which backends are protected by Cloud Armor.
*   `cloudkms.keyRings.list` - To enumerate KMS key rings.
*   `cloudkms.cryptoKeys.list` - To check KMS key rotation policies.
*   `secretmanager.secrets.list` - To enumerate Secret Manager secrets.
*   `secretmanager.secrets.getIamPolicy` - To read secret IAM bindings.
*   `bigquery.datasets.get` - To inspect BigQuery dataset access entries.
*   `dns.managedZones.list` - To check DNSSEC status on managed zones.

### Creating a Custom IAM Role

You can create a custom IAM role named `security_mind_auditor` using the following `gcloud` command. Run this command in your Cloud Shell or any environment where you have the `gcloud` CLI configured.

```bash
gcloud iam roles create security_mind_auditor --project=[YOUR_PROJECT_ID] 
    --title="Security Mind Auditor" 
    --description="Read-only role for the Security Mind application" 
    --permissions="cloudasset.assets.list,containeranalysis.occurrences.list,compute.instances.list,iam.serviceAccountKeys.list,orgpolicy.policy.get,recommender.iamPolicyRecommendations.list,securitycenter.findings.list,securitycenter.sources.list,compute.firewalls.list,compute.zones.list,container.clusters.list,run.services.list,cloudfunctions.functions.list,resourcemanager.projects.getIamPolicy,compute.subnetworks.list,compute.networks.get,compute.securityPolicies.list,compute.backendServices.list,cloudkms.keyRings.list,cloudkms.cryptoKeys.list,secretmanager.secrets.list,secretmanager.secrets.getIamPolicy,bigquery.datasets.get,dns.managedZones.list" 
    --stage=GA
```

Replace `[YOUR_PROJECT_ID]` with the ID of your GCP project.

### Granting the Custom Role

Once the role is created, you can grant it to a service account:

```bash
gcloud projects add-iam-policy-binding [YOUR_PROJECT_ID] 
    --member="serviceAccount:[SERVICE_ACCOUNT_EMAIL]" 
    --role="projects/[YOUR_PROJECT_ID]/roles/security_mind_auditor"
```

Replace `[YOUR_PROJECT_ID]` and `[SERVICE_ACCOUNT_EMAIL]` with your project ID and the email of the service account you are using for Security Mind.
