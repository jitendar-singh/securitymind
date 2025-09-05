# secmind/sub_agents/cloud_compliance/agent.py (rewritten file)

import os
from datetime import datetime, timezone
from google.cloud import asset_v1
from google.cloud import securitycenter_v1
from google.cloud import recommender_v1
from google.cloud import orgpolicy_v2
from google.cloud import iam_admin_v1
from google.cloud.iam_admin_v1 import types
from googleapiclient.discovery import build
from google.oauth2 import service_account
from google.adk.agents import Agent
from google.protobuf.json_format import MessageToDict

def list_gcp_resources(project_id: str, resource_type: str = 'all'):
    # Example: Using Asset API for resource inventory; adjust based on your exact API
    client = asset_v1.AssetServiceClient()  # Or whichever client you're using
    parent = f"projects/{project_id}"
    
    # Call to list resources (this returns a protobuf response or iterable of messages)
    response = client.search_all_resources(request={"scope": parent})  # Or list_projects(), etc.
    
    # The fix: Convert to dict before serializing/returning
    # If response is a single message: resources = MessageToDict(response)
    # If it's an iterable/paginator, convert each item
    resources = []
    for item in response:  # Assuming it's iterable; adjust if it's a single response
        resource_dict = MessageToDict(item._pb if hasattr(item, '_pb') else item)
        resources.append(resource_dict)
    
    # Now you can safely json.dumps(resources) or return it
    return resources  # Or json.dumps(resources) if needed for output

def list_security_sources(parent: str) -> dict:
    """
    Lists security sources in Security Command Center for the given parent (e.g., 'organizations/{org_id}', 'projects/{project_id}', or 'folders/{folder_id}').
    """
    try:
        client = securitycenter_v1.SecurityCenterClient()
        sources = []
        for source in client.list_sources(request={"parent": parent}):
            sources.append({
                "name": source.name,
                "display_name": source.display_name,
                "description": source.description,
                "source_id": source.name.split('/')[-1]  # Extract the source_id
            })
        return {"status": "success", "sources": sources}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_security_posture(parent: str, source_id: str) -> dict:
    """
    Checks cloud security posture using Security Command Center API for overall findings.
    parent: e.g., 'projects/{project_id}' or 'organizations/{org_id}'
    source_id: Optional; if provided, filters to that source; else, queries all ('-').
    """
    try:
        client = securitycenter_v1.SecurityCenterClient()
        source_parent = f"{parent}/sources/{source_id}" if source_id else f"{parent}/sources/-"
        response = client.list_findings(request={"parent": source_parent})
        findings = []
        for finding in response.list_findings_results:
            findings.append({
                "name": finding.finding.name,
                "severity": finding.finding.severity,
                "category": finding.finding.category,
                "description": finding.finding.description,
                "state": finding.finding.state,
                "resource_name": finding.finding.resource_name
            })
        # Basic summary for overall posture
        summary = {
            "total_findings": len(findings),
            "critical_count": sum(1 for f in findings if f['severity'] == 'CRITICAL'),
            "high_count": sum(1 for f in findings if f['severity'] == 'HIGH'),
            "medium_count": sum(1 for f in findings if f['severity'] == 'MEDIUM'),
            "low_count": sum(1 for f in findings if f['severity'] == 'LOW')
        }
        return {"status": "success", "findings": findings, "summary": summary}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_iam_recommendations(project_id: str) -> dict:
    """
    Checks IAM recommendations for least privilege using Recommender API.
    """
    try:
        client = recommender_v1.RecommenderClient()
        parent = f"projects/{project_id}/locations/global/recommenders/google.iam.policy.Recommender"
        print(parent)
        recommendations = []
        for reco in client.list_recommendations(parent=parent):
            recommendations.append({
                "name": reco.name,
                "description": reco.description,
                "priority": reco.priority
            })
        summary = f"{len(recommendations)} IAM recommendations found. Focus on reducing privileges."
        # print(f'recommendations: {recommendations}, summary: {summary}')
        return {"status": "success", "recommendations": recommendations, "summary": summary}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_org_policies(organization_id: str) -> dict:
    """
    Checks organization policies for compliance using Organization Policy API.
    """
    try:
        client = orgpolicy_v2.OrgPolicyClient()
        parent = f"organizations/{organization_id}"
        policies = []
        for policy in client.list_policies(parent=parent):
            policies.append({
                "name": policy.name,
                "rules": [rule.values for rule in policy.rules] if policy.rules else [],
                "etag": policy.etag
            })
        summary = f"{len(policies)} policies listed. Verify compliance rules (e.g., restrict public buckets)."
        return {"status": "success", "policies": policies, "summary": summary}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    
def check_access_keys(project_id: str, max_age_days: int = 90) -> dict:
    """
    Lists and checks IAM service account keys for rotation.
    """
    try:
        # Initialize the IAM client
        client = iam_admin_v1.IAMClient()
        keys = []
        non_compliant = []
        for sa in client.list_service_accounts(request={"name": f"projects/{project_id}"}):
            sa_name = sa.name
            # Build the request
            request = types.ListServiceAccountKeysRequest()
            request.name = f"{sa_name}"
            
            # Call the API
            response = client.list_service_account_keys(request=request)
        
            # If no keys, or for additional logic
            if not response.keys:
                print("No keys found for this service account.")

            for key in response.keys:
                create_time = key.valid_after_time
                age_days = (datetime.now(timezone.utc) - create_time).days
                keys.append({
                    "key_name": key.name,
                    "create_time": str(create_time),
                    "age_days": age_days
                })
                if age_days > max_age_days:
                    non_compliant.append(key.name)
            summary = f"{len(non_compliant)} keys older than {max_age_days} days. Recommend rotation."
        return {"status": "success", "keys": keys, "non_compliant": non_compliant, "summary": summary}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_mfa_and_password_policy(domain: str) -> dict:
    """
    Checks MFA enrollment and password policy using Google Admin SDK.
    domain: Google Workspace domain.
    """
    try:
        credentials = service_account.Credentials.from_service_account_file(
            os.getenv('GOOGLE_API_KEY'),
            scopes=['https://www.googleapis.com/auth/admin.directory.user']
        )
        service = build('admin', 'directory_v1', credentials=credentials)
        
        # MFA check
        users = service.users().list(domain=domain).execute().get('users', [])
        mfa_status = []
        for user in users:
            user_details = service.users().get(userKey=user['primaryEmail']).execute()
            mfa_enabled = user_details.get('isEnrolledIn2Sv', False)
            is_privileged = user_details.get('isAdmin', False) or user_details.get('isDelegatedAdmin', False)
            mfa_status.append({
                "user": user['primaryEmail'],
                "mfa_enabled": mfa_enabled,
                "privileged": is_privileged,
                "note": "Needs MFA" if is_privileged and not mfa_enabled else "Compliant"
            })
        
        # Password policy (simplified; actual policy via Cloud Identity or manual check)
        # Note: Password policy is org-level; fetch via API if enabled
        password_policy = {"min_length": 8, "require_complexity": True}  # Placeholder; use real API if available
        
        non_compliant_mfa = sum(1 for s in mfa_status if not s['mfa_enabled'] and s['privileged'])
        summary = f"{non_compliant_mfa} privileged users without MFA. Password policy: Min length {password_policy['min_length']}, complexity {password_policy['require_complexity']}."
        return {"status": "success", "mfa_status": mfa_status, "password_policy": password_policy, "summary": summary}
    except Exception as e:
        return {"status": "error", "message": str(e)}

cloud_compliance_agent = Agent(
    name="cloud_compliance_agent",
    model="gemini-2.5-flash",
    description="Checks GCP resources, security posture, IAM recommendations, org policies, access keys, MFA, and password policies.",
    instruction="""You are a cloud compliance agent for GCP focused on overall security posture assessment. 
    For queries like 'check overall security posture of GCP project', first ask for parent i.e project_id or org_id if not provided.
    Then, use list_security_sources to discover sources.
    Use check_security_posture with '-' for all sources to get findings and summary.  
    Use list_gcp_resources for resource inventory.
    Use list_security_sources and check_security_posture for SCC findings.
    Optionally, use list_gcp_resources (with asset_types=None for all) to inventory resources and correlate with findings.
    Provide a comprehensive summary: total findings by severity, key risks, recommendations.
    For IAM/compliance:
    - Least privilege: Use check_iam_recommendations (ask for project_id if not already provided).
    - Access key rotation: Use check_access_keys (ask for project_id if not provided and if max_age_days is not provided fallback to use 90 days as default).
    Categorize outputs (e.g., under IAM, Policies).
    Ask for missing info.
    Provide summaries with recommendations (e.g., rotate keys, enable MFA for admins).
    Generate comprehensive report with clear sections (e.g., Overall Security Posture, IAM Controls, Policies).
    Example report format:
    Overall Security Posture:
    1. Total Findings: X
    2. Critical: Y
    3. High: Z
    4. Medium: A
    5. Low: B
    Key Risks:
    - Risk description (e.g., public access to data)
    Recommendations:
    - Fix this, review that, etc.
    IAM Controls:
    1. Recommendations:
    - Fix
    - Fix
    Policies:
    1. Non-Compliant: A
    - Issue summary
    Security Recommendations:
    1. Least Privilege - Use IAM least privilege recommendations.
    2. Policies - Ensure compliance with organization policies.
    3. Access Keys - Rotate IAM service account keys.
    
    Please implement the below instructions to complete the task.
    Provide the list of all GCP resources first.
    Then, check security posture.
    Finally, perform IAM recommendations, organizational policies, access keys, and MFA/ Password policies checks.
    Generate a comprehensive report for the above tasks.
    Include the below details in the report.
    Summary of GCP Resources and Security Findings:
    1. Resource type and details found.
    2. Security findings, categories, severity, state.
    3. Detailed explanation of any anomalies found.
    4. Provide remediation steps for any vulnerabilities found..
    Ensure that the output is well-structured and easy to read.
    Example format for reporting:
    Highlights of findings: Quick summary of key findings.
    Detailed findings analysis:
        - Detailed description of each finding and its impact.
        - Security posture snapshot (overall score and categories).
    Remediation recommendations:
        - Specific steps to mitigate detected vulnerabilities.
    Ensure the findings and recommendations are actionable and clear.
    Add relevant links for further reading on GCP security best practices.
    For large reports, segment the output to include:
    - Summary
    - Detailed findings
    - Remediation recommendations
    - Findings overview and quick remediation guidelines
    - Security posture snapshot and actionable insights
    - Conclusion and best practices.
    The same details should also be generated for IAM recommendations, organizational policies, access keys, and policies checks.

    """,
    tools=[list_gcp_resources, list_security_sources, check_security_posture, check_iam_recommendations,check_access_keys]
)