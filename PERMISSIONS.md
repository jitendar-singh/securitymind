# Required Permissions

Security Mind is designed to operate with the principle of least privilege. The application only requires read-only access to your cloud environment to perform its security assessments. It does not perform any write operations or configuration changes.

This document outlines the minimum required IAM permissions for each supported cloud provider.

## Google Cloud Platform (GCP)

We recommend creating a custom IAM role with the exact permissions needed to run the compliance checks.

### Required Permissions

The following permissions are required for the GCP service account used by Security Mind:

*   `cloudasset.assets.list` - To list cloud resources.
*   `containeranalysis.occurrences.list` - To list vulnerability occurrences for container images.
*   `compute.instances.list` - To list GCE instances.
*   `iam.serviceAccountKeys.list` - To list service account keys.
*   `orgpolicy.policy.get` - To get organization policies.
*   `recommender.iamPolicyRecommendations.list` - To list IAM recommendations.
*   `securitycenter.findings.list` - To list security findings.
*   `securitycenter.sources.list` - To list security sources.

### Creating a Custom IAM Role

You can create a custom IAM role named `security_mind_auditor` using the following `gcloud` command. Run this command in your Cloud Shell or any environment where you have the `gcloud` CLI configured.

```bash
gcloud iam roles create security_mind_auditor --project=[YOUR_PROJECT_ID] 
    --title="Security Mind Auditor" 
    --description="Read-only role for the Security Mind application" 
    --permissions="cloudasset.assets.list,containeranalysis.occurrences.list,compute.instances.list,iam.serviceAccountKeys.list,orgpolicy.policy.get,recommender.iamPolicyRecommendations.list,securitycenter.findings.list,securitycenter.sources.list" 
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
