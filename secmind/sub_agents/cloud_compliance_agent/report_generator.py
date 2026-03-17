"""
HTML report generator for cloud compliance agent.
"""

import datetime
from typing import Dict, Any, Optional

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
            </div>

            <h2>Security Posture Findings</h2>
            {"<table><tr><th>Severity</th><th>Category</th><th>Description</th><th>Resource</th></tr>" + "".join([f"<tr><td>{f['severity']}</td><td>{f['category']}</td><td>{f['description']}</td><td>{f['resource_name']}</td></tr>" for f in findings]) + "</table>" if findings else "<p>No security posture findings.</p>"}

            <h2>IAM Recommendations</h2>
            {"<table><tr><th>Priority</th><th>Description</th><th>Recommender</th><th>Details</th></tr>" + "".join([f"<tr><td>{r['priority']}</td><td>{r['description']}</td><td>{r['recommender_subtype']}</td><td>{'<br>'.join([f'<b>Path:</b> {op.get("path", "N/A")}<br><b>Op:</b> {op.get("op", "N/A")}<br><b>Value:</b> {op.get("value", "N/A")}' for op in r.get('details', {}).get('operations', [])])}</td></tr>" for r in iam_recs]) + "</table>" if iam_recs else "<p>No IAM recommendations found.</p>"}

            <h2>Organization Policies</h2>
            {"<table><tr><th>Constraint</th><th>Rules</th></tr>" + "".join([f"<tr><td>{p['constraint']}</td><td>{str(p['rules'])}</td></tr>" for p in org_policies]) + "</table>" if org_policies else "<p>No organization policies found.</p>"}

            <h2>Non-Compliant Access Keys (&gt;{access_keys.get('max_age_days', 90)} days)</h2>
            {"<table><tr><th>Service Account</th><th>Key Name</th><th>Age (days)</th></tr>" + "".join([f"<tr><td>{k['service_account']}</td><td>{k['key_name']}</td><td>{k['age_days']}</td></tr>" for k in non_compliant_keys]) + "</table>" if non_compliant_keys else "<p>No non-compliant access keys found.</p>"}

            <div class="footer">
                <p>Generated by Security Mind AI</p>
            </div>
        </div>
    </body>
    </html>
    """
    return html
