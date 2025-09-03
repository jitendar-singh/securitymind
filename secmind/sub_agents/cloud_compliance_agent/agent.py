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

def list_gcp_resources(project_id: str, asset_types: str) -> dict:
    """
    Lists GCP resources using Cloud Asset Inventory API.
    asset_types: Optional comma-separated list; if None, lists all types.
    """
    try:
        client = asset_v1.AssetServiceClient()
        parent = f"projects/{project_id}"
        request = asset_v1.ListAssetsRequest(
            parent=parent,
            content_type=asset_v1.ContentType.RESOURCE,
        )
        if asset_types:
            request.asset_types = asset_types.split(',')
        response = client.list_assets(request=request)
        resources = []
        for asset in response.assets:
            resources.append({
                "name": asset.name,
                "type": asset.asset_type,
                "details": asset.resource.data if asset.resource else {}
            })
        return {"status": "success", "resources": resources}
    except Exception as e:
        return {"status": "error", "message": str(e)}

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
        recommendations = []
        for reco in client.list_recommendations(parent=parent):
            recommendations.append({
                "name": reco.name,
                "description": reco.description,
                "priority": reco.priority,
                "content": reco.content.overview if reco.content else {}
            })
        summary = f"{len(recommendations)} IAM recommendations found. Focus on reducing privileges."
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
    Explain any anomalies or security issues found.
    Summarize findings in a comprehensive format.
    Example output:
    Summary of GCP Resources and Security Findings:
    1. Resource type and details found.
    2. Security findings, categories, severity, state.
    3. Detailed explanation of any anomalies found.
    4. Provide remediation steps for any vulnerabilities found.
    5. For IAM/compliance:
    - Least privilege: Use check_iam_recommendations (ask for project_id).
    - Org policies: Use check_org_policies (ask for organization_id).
    - Access key rotation: Use check_access_keys (ask for project_id/max_age_days).
    - MFA/password policy: Use check_mfa_and_password_policy (ask for domain).
    Categorize outputs (e.g., under IAM, Policies).
    Ask for missing info.
    Provide summaries with recommendations (e.g., rotate keys, enable MFA for admins).
  
    Example recommendation: "Vulnerabilities found. Please address these immediately by checking your GCP resource configurations and hardening guidelines."
    For high severity findings, generate detailed remediation steps.
    Also generate a detailed security posture report.
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
    """,
    tools=[list_gcp_resources, list_security_sources, check_security_posture, check_iam_recommendations, check_org_policies, check_mfa_and_password_policy,check_access_keys]
)

























# # secmind/sub_agents/cloud_compliance/agent.py (updated file)

# import os
# from pytz import timezone
# from google.adk.agents import Agent
# from google.cloud import asset_v1
# from google.cloud import securitycenter_v1
# from google.cloud import recommender_v1
# # from google.admin.directory_v1 import DirectoryService
# from googleapiclient.discovery import build
# from google.cloud import iam_v2
# # from google.cloud import identity_v1
# from datetime import datetime


# def list_gcp_resources(project_id: str, asset_types: str) -> dict:
#     """
#     Lists GCP resources using Cloud Asset Inventory API.
#     asset_types: Optional comma-separated list; if None, lists all types.
#     """
#     try:
#         client = asset_v1.AssetServiceClient()
#         parent = f"projects/{project_id}"
#         request = asset_v1.ListAssetsRequest(
#             parent=parent,
#             content_type=asset_v1.ContentType.RESOURCE,
#         )
#         if asset_types:
#             request.asset_types = asset_types.split(',')
#         response = client.list_assets(request=request)
#         resources = []
#         for asset in response.assets:
#             resources.append({
#                 "name": asset.name,
#                 "type": asset.asset_type,
#                 "details": asset.resource.data if asset.resource else {}
#             })
#         return {"status": "success", "resources": resources}
#     except Exception as e:
#         return {"status": "error", "message": str(e)}

# def list_security_sources(parent: str) -> dict:
#     """
#     Lists security sources in Security Command Center for the given parent (e.g., 'organizations/{org_id}', 'projects/{project_id}', or 'folders/{folder_id}').
#     """
#     try:
#         client = securitycenter_v1.SecurityCenterClient()
#         sources = []
#         for source in client.list_sources(request={"parent": parent}):
#             sources.append({
#                 "name": source.name,
#                 "display_name": source.display_name,
#                 "description": source.description,
#                 "source_id": source.name.split('/')[-1]  # Extract the source_id
#             })
#         return {"status": "success", "sources": sources}
#     except Exception as e:
#         return {"status": "error", "message": str(e)}

# def check_security_posture(parent: str, source_id: str) -> dict:
#     """
#     Checks cloud security posture using Security Command Center API for overall findings.
#     parent: e.g., 'projects/{project_id}' or 'organizations/{org_id}'
#     source_id: Optional; if provided, filters to that source; else, queries all ('-').
#     """
#     try:
#         client = securitycenter_v1.SecurityCenterClient()
#         source_parent = f"{parent}/sources/{source_id}" if source_id else f"{parent}/sources/-"
#         response = client.list_findings(request={"parent": source_parent})
#         findings = []
#         for finding in response.list_findings_results:
#             findings.append({
#                 "name": finding.finding.name,
#                 "severity": finding.finding.severity,
#                 "category": finding.finding.category,
#                 "description": finding.finding.description,
#                 "state": finding.finding.state,
#                 "resource_name": finding.finding.resource_name
#             })
#         # Basic summary for overall posture
#         summary = {
#             "total_findings": len(findings),
#             "critical_count": sum(1 for f in findings if f['severity'] == 'CRITICAL'),
#             "high_count": sum(1 for f in findings if f['severity'] == 'HIGH'),
#             "medium_count": sum(1 for f in findings if f['severity'] == 'MEDIUM'),
#             "low_count": sum(1 for f in findings if f['severity'] == 'LOW')
#         }
#         return {"status": "success", "findings": findings, "summary": summary}
#     except Exception as e:
#         return {"status": "error", "message": str(e)}

# def check_iam_least_privilege(parent: str ) -> dict:
#     """
#     Checks for over-privileged IAM roles using IAM Recommender API.
#     parent: e.g., 'projects/{project_id}' or 'organizations/{org_id}'; defaults to env var if None.
#     """
#     if not parent:
#         parent = f"projects/{os.getenv('GOOGLE_CLOUD_PROJECT')}"
#     try:
#         client = recommender_v1.RecommenderClient()
#         recommendations = []
#         for reco in client.list_recommendations(parent=parent + '/locations/global/recommenders/google.iam.policy.Recommender'):
#             recommendations.append({
#                 "name": reco.name,
#                 "description": reco.description,
#                 "priority": reco.priority,
#                 "content": reco.content.overview if reco.content else {}
#             })
#         return {"status": "success", "recommendations": recommendations, "summary": f"{len(recommendations)} over-privileged roles detected."}
#     except Exception as e:
#         return {"status": "error", "message": str(e)}

# # def check_mfa_enabled(domain: str) -> dict:
# #     """
# #     Checks MFA status for users using Google Admin SDK (requires super admin credentials).
# #     domain: Your Google Workspace domain (e.g., 'example.com').
# #     """
# #     try:
# #         credentials = # Assume service account credentials setup
# #         service = build('admin', 'directory_v1', credentials=credentials)
# #         users = service.users().list(domain=domain).execute().get('users', [])
# #         mfa_status = []
# #         for user in users:
# #             user_id = user['id']
# #             mfa_info = service.users().get(userKey=user_id, projection='full').execute().get('isEnrolledIn2Sv', False)
# #             privileged = 'admin' in user.get('roles', [])  # Simplified check
# #             mfa_status.append({
# #                 "user": user['primaryEmail'],
# #                 "mfa_enabled": mfa_info,
# #                 "privileged": privileged,
# #                 "note": "Needs MFA" if privileged and not mfa_info else "Compliant"
# #             })
# #         non_compliant = sum(1 for s in mfa_status if not s['mfa_enabled'])
# #         return {"status": "success", "mfa_status": mfa_status, "summary": f"{non_compliant} users without MFA."}
# #     except Exception as e:
# #         return {"status": "error", "message": str(e)}

# # def get_password_policy(org_id: str) -> dict:
# #     """
# #     Gets password policy using Cloud Identity API.
# #     org_id: Your organization ID.
# #     """
# #     try:
# #         client = identity_v1.CloudIdentityServiceClient()
# #         policy = client.get_password_policy(name=f"organizations/{org_id}/passwordPolicy")
# #         return {"status": "success", "policy": {
# #             "min_length": policy.min_length,
# #             "require_uppercase": policy.require_uppercase,
# #             "require_lowercase": policy.require_lowercase,
# #             "require_numeric": policy.require_numeric,
# #             "require_symbols": policy.require_symbols,
# #             "reuse_limit": policy.reuse_limit
# #         }, "summary": "Password policy retrieved."}
# #     except Exception as e:
# #         return {"status": "error", "message": str(e)}

# def check_access_key_rotation(project_id: str, max_age_days: int = 90) -> dict:
#     """
#     Checks for old access keys using IAM API.
#     Flags keys older than max_age_days.
#     """
#     try:
#         client = iam_v2.IAMClient()
#         keys = []
#         non_compliant = []
#         for sa in client.list_service_accounts(parent=f"projects/{project_id}"):
#             sa_name = sa.name
#             for key in client.list_keys(parent=sa_name):
#                 create_time = key.create_time
#                 age_days = (datetime.now(tz=timezone.utc) - create_time).days
#                 keys.append({
#                     "key_name": key.name,
#                     "create_time": str(create_time),
#                     "age_days": age_days
#                 })
#                 if age_days > max_age_days:
#                     non_compliant.append(key.name)
#         return {"status": "success", "keys": keys, "non_compliant": non_compliant, "summary": f"{len(non_compliant)} keys need rotation."}
#     except Exception as e:
#         return {"status": "error", "message": str(e)}

# cloud_compliance_agent = Agent(
#     name="cloud_compliance_agent",
#     model="gemini-2.5-flash",
#     description="Checks GCP resources, cloud security posture, and IAM compliance.",
#     instruction="""You are a cloud compliance agent for GCP focused on overall security posture assessment. 
#     For queries like 'check overall security posture of GCP project', first ask for parent i.e project_id or org_id if not provided.
#     Then, use list_security_sources to discover sources.
#     Use check_security_posture with '-' for all sources to get findings and summary.
#     Optionally, use list_gcp_resources (with asset_types=None for all) to inventory resources and correlate with findings.
#     Provide a comprehensive summary: total findings by severity, key risks, recommendations (e.g., enable SCC Premium for advanced posture management).
#     If needed, suggest enabling Security Command Center in the project.
#     Explain any anomalies or security issues found.
#     Also provide recommendations for remediation if any vulnerabilities are detected.
#     Summarize findings in a comprehensive format.
#     Example output:
#     Summary of GCP Resources and Security Findings:
#     1. Resource type and details found.
#     2. Security findings, categories, severity, state.
#     3. Detailed explanation of any anomalies found.
#     4. Provide remediation steps for any vulnerabilities found.
#     5. For IAM category:
#     - Least privilege: Use check_iam_least_privilege.
#     - MFA: Use check_mfa_enabled (ask for domain).
#     - Password policy: Use get_password_policy (ask for org_id).
#     - Key rotation: Use check_access_key_rotation (ask for project_id and max_age_days if needed).
#     Categorize outputs under IAM.
#     For general posture, use existing tools.
#     Ask for missing info.
#     Example recommendation: "Vulnerabilities found. Please address these immediately by checking your GCP resource configurations and hardening guidelines."
#     For high severity findings, generate detailed remediation steps.
#     Also generate a detailed security posture report.
#     Ensure that the output is well-structured and easy to read.
#     Example format for reporting:
#     Highlights of findings: Quick summary of key findings.
#     Detailed findings analysis:
#         - Detailed description of each finding and its impact.
#         - Security posture snapshot (overall score and categories).
#     Remediation recommendations:
#         - Specific steps to mitigate detected vulnerabilities.
#     Ensure the findings and recommendations are actionable and clear.
#     Add relevant links for further reading on GCP security best practices.
#     For large reports, segment the output to include:
#     - Summary
#     - Detailed findings
#     - Remediation recommendations
#     - Findings overview and quick remediation guidelines
#     - Security posture snapshot and actionable insights
#     - Conclusion and best practices.
    
#     Ensure the report is thorough, concise, and provides clear actionable insights.
#     Provide clear insights, step-by-step recommendations for immediate improvements, and compliance guidelines.
#     Prioritize high severity findings and ensure all remediation steps are detailed.
#     Separate high severity from medium severity findings clearly and emphasize on high severity immediately.
#     Ensure no data is omitted or oversimplified.
#     Make sure the output is comprehensive and detailed.""",
#     tools=[list_gcp_resources, list_security_sources, check_security_posture, check_iam_least_privilege, check_access_key_rotation]
# )



# =======================================




# # import os
# # from google.cloud import asset_v1
# # from google.cloud import securitycenter_v1
# # from google.adk.agents import Agent

# # def list_gcp_resources(project_id: str, asset_types: str) -> dict:
# #     """
# #     Lists GCP resources using Cloud Asset Inventory API.
# #     asset_types: Optional comma-separated list; if None, lists all types.
# #     """
# #     try:
# #         client = asset_v1.AssetServiceClient()
# #         parent = f"projects/{project_id}"
# #         request = asset_v1.ListAssetsRequest(
# #             parent=parent,
# #             content_type=asset_v1.ContentType.RESOURCE,
# #         )
# #         if asset_types:
# #             request.asset_types = asset_types.split(',')
# #         response = client.list_assets(request=request)
# #         resources = []
# #         for asset in response.assets:
# #             resources.append({
# #                 "name": asset.name,
# #                 "type": asset.asset_type,
# #                 "details": asset.resource.data if asset.resource else {}
# #             })
# #         return {"status": "success", "resources": resources}
# #     except Exception as e:
# #         return {"status": "error", "message": str(e)}

# # def list_security_sources(parent: str) -> dict:
# #     """
# #     Lists security sources in Security Command Center for the given parent (e.g., 'organizations/{org_id}', 'projects/{project_id}', or 'folders/{folder_id}').
# #     """
# #     try:
# #         client = securitycenter_v1.SecurityCenterClient()
# #         sources = []
# #         for source in client.list_sources(request={"parent": parent}):
# #             sources.append({
# #                 "name": source.name,
# #                 "display_name": source.display_name,
# #                 "description": source.description,
# #                 "source_id": source.name.split('/')[-1]  # Extract the source_id
# #             })
# #         return {"status": "success", "sources": sources}
# #     except Exception as e:
# #         return {"status": "error", "message": str(e)}

# # def check_security_posture(parent: str, source_id: str) -> dict:
# #     """
# #     Checks cloud security posture using Security Command Center API for overall findings.
# #     parent: e.g., 'projects/{project_id}' or 'organizations/{org_id}'
# #     source_id: Optional; if provided, filters to that source; else, queries all ('-').
# #     """
# #     try:
# #         client = securitycenter_v1.SecurityCenterClient()
# #         source_parent = f"{parent}/sources/{source_id}" if source_id else f"{parent}/sources/-"
# #         response = client.list_findings(request={"parent": source_parent})
# #         findings = []
# #         for finding in response.list_findings_results:
# #             findings.append({
# #                 "name": finding.finding.name,
# #                 "severity": finding.finding.severity,
# #                 "category": finding.finding.category,
# #                 "description": finding.finding.description,
# #                 "state": finding.finding.state,
# #                 "resource_name": finding.finding.resource_name
# #             })
# #         # Basic summary for overall posture
# #         summary = {
# #             "total_findings": len(findings),
# #             "critical_count": sum(1 for f in findings if f['severity'] == 'CRITICAL'),
# #             "high_count": sum(1 for f in findings if f['severity'] == 'HIGH'),
# #             "medium_count": sum(1 for f in findings if f['severity'] == 'MEDIUM'),
# #             "low_count": sum(1 for f in findings if f['severity'] == 'LOW')
# #         }
# #         return {"status": "success", "findings": findings, "summary": summary}
# #     except Exception as e:
# #         return {"status": "error", "message": str(e)}

# # cloud_compliance_agent = Agent(
# #     name="cloud_compliance_agent",
# #     model="gemini-2.5-flash",
# #     description="Checks GCP resources and overall cloud security posture.",
# #     instruction="""You are a cloud compliance agent for GCP focused on overall security posture assessment. 
# #     For queries like 'check overall security posture of GCP project', first ask for parent i.e project_id or org_id if not provided.
# #     Then, use list_security_sources to discover sources.
# #     Use check_security_posture with '-' for all sources to get findings and summary.
# #     Optionally, use list_gcp_resources (with asset_types=None for all) to inventory resources and correlate with findings.
# #     Provide a comprehensive summary: total findings by severity, key risks, recommendations (e.g., enable SCC Premium for advanced posture management).
# #     If needed, suggest enabling Security Command Center in the project.
# #     Explain any anomalies or security issues found.
# #     Also provide recommendations for remediation if any vulnerabilities are detected.
# #     Summarize findings in a comprehensive format.
# #     Example output:
# #     Summary of GCP Resources and Security Findings:
# #     1. Resource type and details found.
# #     2. Security findings, categories, severity, state.
# #     3. Detailed explanation of any anomalies found.
# #     4. Provide remediation steps for any vulnerabilities found.
# #     Example recommendation: "Vulnerabilities found. Please address these immediately by checking your GCP resource configurations and hardening guidelines."
# #     For high severity findings, generate detailed remediation steps.
# #     Also generate a detailed security posture report.
# #     Ensure that the output is well-structured and easy to read.
# #     Example format for reporting:
# #     Highlights of findings: Quick summary of key findings.
# #     Detailed findings analysis:
# #         - Detailed description of each finding and its impact.
# #         - Security posture snapshot (overall score and categories).
# #     Remediation recommendations:
# #         - Specific steps to mitigate detected vulnerabilities.
# #     Ensure the findings and recommendations are actionable and clear.
# #     Add relevant links for further reading on GCP security best practices.
# #     For large reports, segment the output to include:
# #     - Summary
# #     - Detailed findings
# #     - Remediation recommendations
# #     - Findings overview and quick remediation guidelines
# #     - Security posture snapshot and actionable insights
# #     - Conclusion and best practices.
# #     For IAM category:
# #     - Least privilege: Use check_iam_least_privilege.
# #     - MFA: Use check_mfa_enabled (ask for domain).
# #     - Password policy: Use get_password_policy (ask for org_id).
# #     - Key rotation: Use check_access_key_rotation (ask for project_id and max_age_days if needed).
# #     Categorize outputs under IAM.
# #     For general posture, use existing tools.
# # Ask for missing info.
# #     Ensure the report is thorough, concise, and provides clear actionable insights.
# #     Provide clear insights, step-by-step recommendations for immediate improvements, and compliance guidelines.
# #     Prioritize high severity findings and ensure all remediation steps are detailed.
# #     Separate high severity from medium severity findings clearly and emphasize on high severity immediately.
# #     Ensure no data is omitted or oversimplified.
# #     Make sure the output is comprehensive and detailed.""",
# #     tools=[list_gcp_resources, list_security_sources, check_security_posture]
# # )