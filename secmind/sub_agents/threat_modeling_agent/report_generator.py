"""HTML report generator for the multi-framework threat modeling agent."""

from __future__ import annotations

import base64
import datetime
import html
import os
from typing import Any, Dict, Iterable, List


def _h(text: Any) -> str:
    """HTML-escape any value for safe embedding."""
    return html.escape("" if text is None else str(text))


def _risk_class(score: Any) -> str:
    if isinstance(score, (int, float)):
        if score > 70:
            return "risk-score-high"
        if score > 40:
            return "risk-score-medium"
    return "risk-score-low"


def _technique_link(framework: str, technique_id: str) -> str:
    if not technique_id:
        return ""
    fw = (framework or "").upper()
    if fw == "ATLAS":
        # ATLAS sub-technique URLs use the parent ID
        base = technique_id.split(".")[0]
        return f"https://atlas.mitre.org/techniques/{base}"
    if fw == "ATT&CK":
        if "." in technique_id:
            head, tail = technique_id.split(".", 1)
            return f"https://attack.mitre.org/techniques/{head}/{tail}/"
        return f"https://attack.mitre.org/techniques/{technique_id}/"
    return ""


def _technique_cell(threat: Dict[str, Any]) -> str:
    tid = threat.get("technique_id")
    if not tid:
        return "—"
    link = _technique_link(threat.get("framework", ""), tid)
    if link:
        return f'<a href="{_h(link)}" target="_blank" rel="noopener">{_h(tid)}</a>'
    return _h(tid)


def _xref_cell(threat: Dict[str, Any]) -> str:
    xrefs = threat.get("cross_references") or []
    if not xrefs:
        return ""
    badges = "".join(
        f'<span class="xref-badge">{_h(x)}</span>' for x in xrefs if x
    )
    return badges


def _embed_dfd(dfd_path: str | None) -> str:
    if not dfd_path:
        return "<p>No DFD generated.</p>"
    if not os.path.exists(dfd_path):
        return f"<p>DFD image not found at: {_h(dfd_path)}</p>"
    try:
        with open(dfd_path, "rb") as f:
            encoded = base64.b64encode(f.read()).decode("utf-8")
        return f'<img src="data:image/png;base64,{encoded}" alt="Data Flow Diagram">'
    except Exception as exc:
        return f"<p>Error rendering DFD: {_h(exc)}</p>"


def _threats_table(threats: Iterable[Dict[str, Any]]) -> str:
    threats = list(threats)
    if not threats:
        return "<p>No threats identified for this framework.</p>"
    rows = []
    for t in threats:
        rows.append(
            "<tr>"
            f"<td>{_h(t.get('threat'))}</td>"
            f"<td>{_h(t.get('description'))}</td>"
            f"<td>{_h(t.get('category'))}</td>"
            f"<td>{_technique_cell(t)}</td>"
            f"<td>{_h(t.get('likelihood'))}</td>"
            f"<td>{_h(t.get('impact'))}</td>"
            f"<td>{_h(', '.join(t.get('affected_components') or []))}</td>"
            f"<td>{_xref_cell(t)}</td>"
            "</tr>"
        )
    return (
        "<table><tr>"
        "<th>Threat</th><th>Description</th><th>Category</th>"
        "<th>Technique ID</th><th>Likelihood</th><th>Impact</th>"
        "<th>Affected Components</th><th>Cross-refs</th>"
        "</tr>" + "".join(rows) + "</table>"
    )


def _framework_section(
    framework_name: str,
    threats: List[Dict[str, Any]],
    score: int,
    overview: str,
) -> str:
    return f"""
            <section class="framework-section">
              <div class="framework-header">
                <h3>{_h(framework_name)}</h3>
                <div class="summary-item {_risk_class(score)}">
                  <div>Framework risk</div>
                  <div class="value">{_h(score)}</div>
                </div>
              </div>
              {f'<p class="framework-overview">{_h(overview)}</p>' if overview else ''}
              {_threats_table(threats)}
            </section>
            """


def _vulnerabilities_section(vulns: List[Dict[str, Any]]) -> str:
    if not vulns:
        return "<p>No vulnerabilities found.</p>"
    rows = "".join(
        "<tr>"
        f"<td>{_h(v.get('vulnerability'))}</td>"
        f"<td>{_h(v.get('description'))}</td>"
        f"<td>{_h(v.get('severity'))}</td>"
        f"<td>{_h(v.get('component'))}</td>"
        f"<td>{_h(v.get('cwe_id') or 'N/A')}</td>"
        f"<td>{_h(v.get('remediation'))}</td>"
        "</tr>"
        for v in vulns
    )
    return (
        "<table><tr>"
        "<th>Vulnerability</th><th>Description</th><th>Severity</th>"
        "<th>Component</th><th>CWE</th><th>Remediation</th>"
        "</tr>" + rows + "</table>"
    )


def _recommendations_section(recs: Dict[str, List[str]]) -> str:
    if not recs:
        return "<p>No recommendations.</p>"
    chunks = []
    for category, items in recs.items():
        if not items:
            continue
        title = category.replace("_", " ").title()
        lis = "".join(f"<li>{_h(item)}</li>" for item in items)
        chunks.append(f"<h3>{_h(title)}</h3><ul>{lis}</ul>")
    return "".join(chunks) if chunks else "<p>No recommendations.</p>"


def _compliance_section(notes: List[str] | None) -> str:
    if not notes:
        return "<p>No compliance notes.</p>"
    items = "".join(f"<li>{_h(n)}</li>" for n in notes)
    return f"<ul>{items}</ul>"


def _frameworks_applied_badges(names: List[str]) -> str:
    if not names:
        return ""
    return "".join(f'<span class="fw-badge">{_h(n)}</span>' for n in names)


def generate_html_report(data: Dict[str, Any]) -> str:
    """Render a multi-framework threat model report as HTML."""
    report_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    overview = data.get("overview", "No overview provided")
    risk_score = data.get("risk_score", "N/A")
    frameworks_applied: List[str] = data.get("frameworks_applied") or []
    framework_scores: Dict[str, int] = data.get("framework_scores") or {}
    framework_overviews: Dict[str, str] = data.get("framework_overviews") or {}
    threats: List[Dict[str, Any]] = data.get("identified_threats") or []
    vulnerabilities = data.get("vulnerabilities") or []
    recommendations = data.get("recommendations") or {}
    compliance_notes = data.get("compliance_notes") or []
    dfd_path = data.get("dfd")

    threats_by_framework: Dict[str, List[Dict[str, Any]]] = {}
    for t in threats:
        threats_by_framework.setdefault(t.get("framework", "Unknown"), []).append(t)

    framework_sections = "".join(
        _framework_section(
            name,
            threats_by_framework.get(name, []),
            framework_scores.get(name, 0),
            framework_overviews.get(name, ""),
        )
        for name in frameworks_applied
    )

    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Threat Model Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f4f4; color: #333; }}
            .container {{ width: 80%; margin: 20px auto; background: #fff; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
            h1, h2, h3 {{ color: #333; border-bottom: 2px solid #4CAF50; padding-bottom: 10px; }}
            h1 {{ text-align: center; }}
            .disclaimer {{ background-color: #fff3cd; color: #856404; padding: 15px; margin-bottom: 20px; border: 1px solid #ffeeba; border-radius: 5px; }}
            .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 20px; }}
            .summary-item {{ background: #f9f9f9; padding: 15px; border-radius: 5px; border-left: 5px solid #4CAF50; }}
            .summary-item .value {{ font-size: 2em; font-weight: bold; }}
            .risk-score-high {{ border-color: #f44336; }}
            .risk-score-medium {{ border-color: #ff9800; }}
            .risk-score-low {{ border-color: #4caf50; }}
            table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 0.9em; }}
            th, td {{ padding: 10px; border: 1px solid #ddd; text-align: left; vertical-align: top; }}
            th {{ background-color: #f2f2f2; }}
            tr:nth-child(even) {{ background-color: #f9f9f9; }}
            .dfd-container {{ text-align: center; margin-bottom: 20px; }}
            .dfd-container img {{ max-width: 100%; height: auto; }}
            .footer {{ text-align: center; margin-top: 20px; font-size: 0.9em; color: #777; }}
            .fw-badge {{ display: inline-block; padding: 4px 10px; margin: 2px; background: #1976d2; color: #fff; border-radius: 12px; font-size: 0.85em; }}
            .xref-badge {{ display: inline-block; padding: 2px 6px; margin: 1px; background: #eee; color: #333; border-radius: 8px; font-size: 0.8em; border: 1px solid #ccc; }}
            .framework-section {{ margin-bottom: 30px; padding: 15px; background: #fafafa; border-radius: 5px; border-left: 4px solid #1976d2; }}
            .framework-header {{ display: flex; justify-content: space-between; align-items: center; gap: 20px; }}
            .framework-header h3 {{ border-bottom: none; margin: 0; }}
            .framework-overview {{ font-style: italic; color: #555; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Threat Model Report</h1>
            <p><strong>Report Date:</strong> {_h(report_date)}</p>

            <div class="disclaimer">
                <p>The threats and vulnerabilities identified in this document are theoretical findings from the threat modeling exercise and do not represent confirmed or active security incidents.</p>
            </div>

            <h2>Executive Summary</h2>
            <p>{_h(overview)}</p>
            <div class="summary-grid">
                <div class="summary-item {_risk_class(risk_score)}">
                    <div>Aggregate Risk Score</div>
                    <div class="value">{_h(risk_score)}</div>
                </div>
                <div class="summary-item">
                    <div>Frameworks Applied</div>
                    <div>{_frameworks_applied_badges(frameworks_applied)}</div>
                </div>
            </div>

            <h2>Data Flow Diagram</h2>
            <div class="dfd-container">
                {_embed_dfd(dfd_path)}
            </div>

            <h2>Identified Threats by Framework</h2>
            {framework_sections if framework_sections else "<p>No threats identified.</p>"}

            <h2>Vulnerabilities</h2>
            {_vulnerabilities_section(vulnerabilities)}

            <h2>Recommendations</h2>
            {_recommendations_section(recommendations)}

            <h2>Compliance Notes</h2>
            {_compliance_section(compliance_notes)}

            <div class="footer">
                <p>Generated by Security Mind AI</p>
            </div>
        </div>
    </body>
    </html>
    """
