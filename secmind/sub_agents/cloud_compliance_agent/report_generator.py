"""
HTML report generator for cloud compliance agent.
"""

import datetime
from typing import Dict, Any, Optional
import json

def _format_value(value: Any) -> str:
    """Format a value for HTML display."""
    if isinstance(value, dict):
        return "<br>".join([f"&nbsp;&nbsp;<b>{k}:</b> {_format_value(v)}" for k, v in value.items()])
    elif isinstance(value, list):
        return "<br>".join([f"&nbsp;&nbsp;- {_format_value(i)}" for i in value])
    else:
        return str(value) if value is not None else "N/A"

def generate_html_report(data: Dict[str, Any], parent: str, cloud: str) -> str:
    """
    Generate an HTML report from compliance data.

    Args:
        data: Dictionary containing compliance data from various checks.
        parent: The cloud parent (project or organization).
        cloud: The cloud provider (e.g., "gcp", "aws", "azure").

    Returns:
        HTML report as a string.
    """
    report_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cloud_name = cloud.upper()

    # Extract data with fallbacks
    posture = data.get("posture", {})
    findings = posture.get("findings", [])
    summary = posture.get("summary", {})
    iam_recs = data.get("iam_recommendations", [])
    org_policies = data.get("org_policies", [])
    access_keys = data.get("access_keys", {})
    non_compliant_keys = access_keys.get("non_compliant", [])
    public_buckets_data = data.get("public_gcs_buckets", {})
    public_buckets = public_buckets_data.get("public_buckets", [])
    risky_fw_rules = (data.get("risky_firewall_rules") or {}).get("issues", [])
    priv_iam_bindings = (data.get("privileged_iam_bindings") or {}).get("issues", [])
    container_scans = (data.get("container_scan_summary") or {}).get("images", [])
    flow_logs = data.get("vpc_flow_logs") or {}
    flow_logs_disabled = flow_logs.get("disabled", [])
    default_network = data.get("default_network") or {}
    kms_rotation = data.get("kms_rotation") or {}
    kms_non_compliant = kms_rotation.get("non_compliant", [])
    secrets = data.get("secrets") or {}
    stale_secrets = secrets.get("stale", [])
    public_secrets = secrets.get("publicly_bound", [])
    public_bq = (data.get("public_bigquery_datasets") or {}).get("public_datasets", [])
    dnssec_zones_disabled = (data.get("dnssec_status") or {}).get("disabled", [])
    cloud_armor = data.get("cloud_armor_coverage") or {}
    armor_unprotected = cloud_armor.get("internet_facing_unprotected", [])

    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{cloud_name} Security Compliance Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 0;
                padding: 0;
                background-color: #f4f4f4;
                color: #333;
            }}
            .container {{
                width: 80%;
                margin: 20px auto;
                background: #fff;
                padding: 20px;
                box-shadow: 0 0 10px rgba(0,0,0,0.1);
            }}
            h1, h2, h3 {{
                color: #333;
                border-bottom: 2px solid #4CAF50;
                padding-bottom: 10px;
            }}
            h1 {{
                text-align: center;
            }}
            .summary-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin-bottom: 20px;
            }}
            .summary-item {{
                background: #f9f9f9;
                padding: 15px;
                border-radius: 5px;
                border-left: 5px solid #4CAF50;
            }}
            .summary-item .value {{
                font-size: 2em;
                font-weight: bold;
            }}
            .critical {{ border-color: #f44336; }}
            .high {{ border-color: #ff9800; }}
            .medium {{ border-color: #ffc107; }}
            .low {{ border-color: #4caf50; }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-bottom: 20px;
            }}
            th, td {{
                padding: 12px;
                border: 1px solid #ddd;
                text-align: left;
            }}
            th {{
                background-color: #f2f2f2;
            }}
            tr:nth-child(even) {{
                background-color: #f9f9f9;
            }}
            .footer {{
                text-align: center;
                margin-top: 20px;
                font-size: 0.9em;
                color: #777;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>{cloud_name} Security Compliance Report</h1>
            <p><strong>Scope:</strong> {parent}</p>
            <p><strong>Report Date:</strong> {report_date}</p>

            <h2>Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-item critical">
                    <div>Critical Findings</div>
                    <div class="value">{summary.get("critical_count", 0)}</div>
                </div>
                <div class="summary-item high">
                    <div>High Findings</div>
                    <div class="value">{summary.get("high_count", 0)}</div>
                </div>
                <div class="summary-item medium">
                    <div>Medium Findings</div>
                    <div class="value">{summary.get("medium_count", 0)}</div>
                </div>
                <div class="summary-item low">
                    <div>Low Findings</div>
                    <div class="value">{summary.get("low_count", 0)}</div>
                </div>
                <div class="summary-item">
                    <div>IAM Recommendations</div>
                    <div class="value">{len(iam_recs)}</div>
                </div>
                <div class="summary-item">
                    <div>Non-compliant Keys</div>
                    <div class="value">{len(non_compliant_keys)}</div>
                </div>
                 <div class="summary-item">
                    <div>Public GCS Buckets</div>
                    <div class="value">{len(public_buckets)}</div>
                </div>
                <div class="summary-item">
                    <div>Risky FW Rules</div>
                    <div class="value">{len(risky_fw_rules)}</div>
                </div>
                <div class="summary-item">
                    <div>Privileged IAM Bindings</div>
                    <div class="value">{len(priv_iam_bindings)}</div>
                </div>
                <div class="summary-item">
                    <div>Subnets w/o Flow Logs</div>
                    <div class="value">{len(flow_logs_disabled)}</div>
                </div>
                <div class="summary-item">
                    <div>KMS Keys Non-Rotating</div>
                    <div class="value">{len(kms_non_compliant)}</div>
                </div>
                <div class="summary-item">
                    <div>Stale Secrets</div>
                    <div class="value">{len(stale_secrets)}</div>
                </div>
                <div class="summary-item">
                    <div>Public BQ Datasets</div>
                    <div class="value">{len(public_bq)}</div>
                </div>
                <div class="summary-item">
                    <div>Zones w/o DNSSEC</div>
                    <div class="value">{len(dnssec_zones_disabled)}</div>
                </div>
                <div class="summary-item">
                    <div>Unprotected Backends</div>
                    <div class="value">{len(armor_unprotected)}</div>
                </div>
            </div>

            <h2>Security Posture Findings</h2>
            {"<table><tr><th>Severity</th><th>Category</th><th>Description</th><th>Resource</th></tr>" + "".join([f"<tr><td>{f['severity']}</td><td>{f['category']}</td><td>{f['description']}</td><td>{f['resource_name']}</td></tr>" for f in findings]) + "</table>" if findings else "<p>No security posture findings.</p>"}

            <h2>IAM Recommendations</h2>
            {"<table><tr><th>Priority</th><th>Description</th><th>Recommender</th><th>Details</th></tr>" + "".join([f"<tr><td>{r['priority']}</td><td>{r['description']}</td><td>{r['recommender_subtype']}</td><td>{'<br>'.join([f"<b>Resource:</b> {op.get('resource', 'N/A')}<br><b>Path:</b> {op.get('path', 'N/A')}<br><b>Path Filters:</b> {_format_value(op.get('pathFilters'))}<br><b>Value:</b> {_format_value(op.get('value'))}" for op in r.get('details', {}).get('operations', [])])}</td></tr>" for r in iam_recs]) + "</table>" if iam_recs else "<p>No IAM recommendations found.</p>"}

            <h2>Organization Policies</h2>
            {"<table><tr><th>Constraint</th><th>Rules</th></tr>" + "".join([f"<tr><td>{p['constraint']}</td><td>{str(p['rules'])}</td></tr>" for p in org_policies]) + "</table>" if org_policies else "<p>No organization policies found.</p>"}

            <h2>Non-Compliant Access Keys (&gt;{access_keys.get('max_age_days', 90)} days)</h2>
            {"<table><tr><th>Service Account</th><th>Key Name</th><th>Age (days)</th></tr>" + "".join([f"<tr><td>{k['service_account']}</td><td>{k['key_name']}</td><td>{k['age_days']}</td></tr>" for k in non_compliant_keys]) + "</table>" if non_compliant_keys else "<p>No non-compliant access keys found.</p>"}

            <h2>Public GCS Buckets</h2>
            {"<table><tr><th>Bucket Name</th><th>URL</th><th>Exposed Roles</th><th>Exposed Members</th></tr>" + "".join([f"<tr><td>{b['name']}</td><td>{b['url']}</td><td>{b['roles']}</td><td>{', '.join(b['members'])}</td></tr>" for b in public_buckets]) + "</table>" if public_buckets else "<p>No publicly accessible GCS buckets found.</p>"}

            <h2>Risky Firewall Rules</h2>
            {"<table><tr><th>Rule</th><th>Port</th><th>Service</th><th>Source Ranges</th><th>Recommended Action</th></tr>" + "".join([f"<tr><td>{r['name']}</td><td>{r['port']}</td><td>{r['service']}</td><td>{', '.join(r.get('source_ranges', []))}</td><td>{r['recommended_action']}</td></tr>" for r in risky_fw_rules]) + "</table>" if risky_fw_rules else "<p>No firewall rules expose sensitive ports to 0.0.0.0/0.</p>"}

            <h2>Privileged IAM Bindings</h2>
            {"<table><tr><th>Member</th><th>Role</th><th>Issue</th></tr>" + "".join([f"<tr><td>{b['member']}</td><td>{b['role']}</td><td>{b['message']}</td></tr>" for b in priv_iam_bindings]) + "</table>" if priv_iam_bindings else "<p>No overly-permissive or impersonation IAM bindings detected.</p>"}

            <h2>Container Scan Summary</h2>
            {"<table><tr><th>Image</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th></tr>" + "".join([f"<tr><td>{c['image']}</td><td>{c.get('CRITICAL', 0)}</td><td>{c.get('HIGH', 0)}</td><td>{c.get('MEDIUM', 0)}</td><td>{c.get('LOW', 0)}</td></tr>" for c in container_scans]) + "</table>" if container_scans else "<p>No container scan summary available. Use the GCP Workload Security agent's <code>scan_container_image</code> tool to populate this section.</p>"}

            <h2>VPC Flow Logs Disabled</h2>
            {"<table><tr><th>Subnet</th><th>Region</th><th>Network</th><th>Flow Sampling</th></tr>" + "".join([f"<tr><td>{s.get('name', '')}</td><td>{s.get('region', '')}</td><td>{s.get('network', '')}</td><td>{s.get('flow_sampling', 'N/A')}</td></tr>" for s in flow_logs_disabled]) + "</table>" if flow_logs_disabled else "<p>All subnets have VPC flow logs enabled.</p>"}

            <h2>Default Network</h2>
            <p>Default VPC present: <strong>{"yes" if default_network.get("present") else "no"}</strong>{f" — auto_create_subnetworks={default_network.get('auto_create_subnetworks')}, subnetworks={default_network.get('subnetwork_count')}" if default_network.get("present") else ""}.</p>

            <h2>KMS Key Rotation (&gt;{kms_rotation.get('max_rotation_days', 90)} days or no rotation)</h2>
            {"<table><tr><th>Key</th><th>Key Ring</th><th>Location</th><th>Rotation (days)</th><th>Reason</th></tr>" + "".join([f"<tr><td>{k.get('name', '')}</td><td>{k.get('key_ring', '')}</td><td>{k.get('location', '')}</td><td>{k.get('rotation_period_days') if k.get('rotation_period_days') is not None else 'N/A'}</td><td>{k.get('reason', '')}</td></tr>" for k in kms_non_compliant]) + "</table>" if kms_non_compliant else "<p>All KMS keys meet the rotation policy.</p>"}

            <h2>Stale Secrets (&gt;{secrets.get('max_age_days', 90)} days)</h2>
            {"<table><tr><th>Secret</th><th>Age (days)</th><th>Created</th></tr>" + "".join([f"<tr><td>{s.get('name', '')}</td><td>{int(s['age_days']) if s.get('age_days') is not None else 'N/A'}</td><td>{s.get('create_time', '')}</td></tr>" for s in stale_secrets]) + "</table>" if stale_secrets else "<p>No stale secrets.</p>"}

            <h2>Publicly Bound Secrets</h2>
            {"<table><tr><th>Secret</th><th>Bindings</th></tr>" + "".join([f"<tr><td>{s.get('name', '')}</td><td>{', '.join([b.get('role', '') + ' → ' + ', '.join(b.get('members', [])) for b in s.get('bindings', [])])}</td></tr>" for s in public_secrets]) + "</table>" if public_secrets else "<p>No secrets are publicly bound.</p>"}

            <h2>Public BigQuery Datasets</h2>
            {"<table><tr><th>Dataset</th><th>Location</th><th>Exposed Role</th><th>Exposed Principal</th></tr>" + "".join([f"<tr><td>{d.get('dataset_id', '')}</td><td>{d.get('location', '')}</td><td>{d.get('exposed_role', '')}</td><td>{d.get('exposed_principal', '')}</td></tr>" for d in public_bq]) + "</table>" if public_bq else "<p>No publicly accessible BigQuery datasets.</p>"}

            <h2>DNSSEC Disabled Zones</h2>
            {"<table><tr><th>Zone</th><th>DNS Name</th><th>Visibility</th><th>State</th></tr>" + "".join([f"<tr><td>{z.get('name', '')}</td><td>{z.get('dns_name', '')}</td><td>{z.get('visibility', '')}</td><td>{z.get('dnssec_state', '')}</td></tr>" for z in dnssec_zones_disabled]) + "</table>" if dnssec_zones_disabled else "<p>All managed zones have DNSSEC enabled (or none exist).</p>"}

            <h2>Cloud Armor Coverage</h2>
            {"<table><tr><th>Backend Service</th><th>Region</th><th>Scheme</th><th>Has Security Policy?</th></tr>" + "".join([f"<tr><td>{b.get('name', '')}</td><td>{b.get('region', '')}</td><td>{b.get('load_balancing_scheme', '')}</td><td>{'yes' if b.get('has_security_policy') else 'no'}</td></tr>" for b in armor_unprotected]) + "</table>" if armor_unprotected else "<p>All internet-facing backend services have a Cloud Armor security policy attached (or none exist).</p>"}

            <div class="footer">
                <p>Generated by Security Mind AI</p>
            </div>
        </div>
    </body>
    </html>
    """
    return html
