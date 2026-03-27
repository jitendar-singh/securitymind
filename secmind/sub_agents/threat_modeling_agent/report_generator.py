"""
HTML report generator for the threat modeling agent.
"""

import datetime
from typing import Dict, Any
import base64
import os

def generate_html_report(data: Dict[str, Any]) -> str:
    """
    Generate an HTML report from threat model data.

    Args:
        data: Dictionary containing threat model data.

    Returns:
        HTML report as a string.
    """
    report_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    overview = data.get("overview", "No overview provided")
    risk_score = data.get("risk_score", "N/A")
    identified_threats = data.get("identified_threats", [])
    vulnerabilities = data.get("vulnerabilities", [])
    recommendations = data.get("recommendations", {})
    compliance_notes = data.get("compliance_notes", [])
    dfd_path = data.get("dfd")

    dfd_html = ""
    if dfd_path and os.path.exists(dfd_path):
        try:
            with open(dfd_path, "rb") as f:
                dfd_base64 = base64.b64encode(f.read()).decode("utf-8")
                dfd_html = f'<img src="data:image/png;base64,{dfd_base64}" alt="Data Flow Diagram">'
        except Exception as e:
            dfd_html = f"<p>Error rendering DFD: {e}</p>"
    elif dfd_path:
        dfd_html = f"<p>DFD image not found at: {dfd_path}</p>"

    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Threat Model Report</title>
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
            .disclaimer {{
                background-color: #fff3cd;
                color: #856404;
                padding: 15px;
                margin-bottom: 20px;
                border: 1px solid #ffeeba;
                border-radius: 5px;
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
            .risk-score-high {{ border-color: #f44336; }}
            .risk-score-medium {{ border-color: #ff9800; }}
            .risk-score-low {{ border-color: #4caf50; }}
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
            .dfd-container {{
                text-align: center;
                margin-bottom: 20px;
            }}
            .dfd-container img {{
                max-width: 100%;
                height: auto;
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
            <h1>Threat Model Report</h1>
            <p><strong>Report Date:</strong> {report_date}</p>

            <div class="disclaimer">
                <p>The threats and vulnerabilities identified in this document are theoretical findings from the threat modeling exercise and do not represent confirmed or active security incidents.</p>
            </div>

            <h2>Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-item risk-score-{'high' if isinstance(risk_score, int) and risk_score > 70 else 'medium' if isinstance(risk_score, int) and risk_score > 40 else 'low'}">
                    <div>Risk Score</div>
                    <div class="value">{risk_score}</div>
                </div>
            </div>
            <h3>Overview</h3>
            <p>{overview}</p>

            <h2>Data Flow Diagram</h2>
            <div class="dfd-container">
                {dfd_html}
            </div>

            <h2>Identified Threats</h2>
            {"<table><tr><th>Threat</th><th>Description</th><th>STRIDE Category</th><th>Likelihood</th><th>Impact</th><th>Affected Components</th></tr>" + "".join([f"<tr><td>{t['threat']}</td><td>{t['description']}</td><td>{t['stride_category']}</td><td>{t['likelihood']}</td><td>{t['impact']}</td><td>{', '.join(t['affected_components'])}</td></tr>" for t in identified_threats]) + "</table>" if identified_threats else "<p>No identified threats.</p>"}

            <h2>Vulnerabilities</h2>
            {"<table><tr><th>Vulnerability</th><th>Description</th><th>Severity</th><th>Component</th><th>CWE ID</th><th>Remediation</th></tr>" + "".join([f"<tr><td>{v['vulnerability']}</td><td>{v['description']}</td><td>{v['severity']}</td><td>{v['component']}</td><td>{v['cwe_id'] or 'N/A'}</td><td>{v['remediation']}</td></tr>" for v in vulnerabilities]) + "</table>" if vulnerabilities else "<p>No vulnerabilities found.</p>"}

            <h2>Recommendations</h2>
            {"".join([f"<h3>{category.replace('_', ' ').title()}</h3><ul>{''.join([f'<li>{rec}</li>' for rec in rec_list])}</ul>" for category, rec_list in recommendations.items() if rec_list]) if recommendations else "<p>No recommendations.</p>"}

            <h2>Compliance Notes</h2>
            {"<ul>" + "".join([f"<li>{note}</li>" for note in compliance_notes]) + "</ul>" if compliance_notes else "<p>No compliance notes.</p>"}

            <div class="footer">
                <p>Generated by Security Mind AI</p>
            </div>
        </div>
    </body>
    </html>
    """
    return html
