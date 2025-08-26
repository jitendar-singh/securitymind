import os
from google.cloud import asset_v1
from google.cloud import securitycenter_v1
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

cloud_compliance_agent = Agent(
    name="cloud_compliance_agent",
    model="gemini-2.5-flash",
    description="Checks GCP resources and overall cloud security posture.",
    instruction="""You are a cloud compliance agent for GCP focused on overall security posture assessment. 
    For queries like 'check overall security posture of GCP project', first ask for parent i.e project_id or org_id if not provided.
    Then, use list_security_sources to discover sources.
    Use check_security_posture with '-' for all sources to get findings and summary.
    Optionally, use list_gcp_resources (with asset_types=None for all) to inventory resources and correlate with findings.
    Provide a comprehensive summary: total findings by severity, key risks, recommendations (e.g., enable SCC Premium for advanced posture management).
    If needed, suggest enabling Security Command Center in the project.
    Explain any anomalies or security issues found.
    Also provide recommendations for remediation if any vulnerabilities are detected.
    Summarize findings in a comprehensive format.
    Example output:
    Summary of GCP Resources and Security Findings:
    1. Resource type and details found.
    2. Security findings, categories, severity, state.
    3. Detailed explanation of any anomalies found.
    4. Provide remediation steps for any vulnerabilities found.
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
    Ensure the report is thorough, concise, and provides clear actionable insights.
    Provide clear insights, step-by-step recommendations for immediate improvements, and compliance guidelines.
    Prioritize high severity findings and ensure all remediation steps are detailed.
    Separate high severity from medium severity findings clearly and emphasize on high severity immediately.
    Ensure no data is omitted or oversimplified.
    Make sure the output is comprehensive and detailed.""",
    tools=[list_gcp_resources, list_security_sources, check_security_posture]
)