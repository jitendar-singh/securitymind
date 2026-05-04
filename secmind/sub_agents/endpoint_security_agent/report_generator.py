"""HTML report generator for endpoint_security_agent.

Mirrors the visual style of cloud_compliance_agent/report_generator.py — same
``.summary-grid`` / ``.summary-item`` / severity colour classes / footer — so
the Reports page renders both consistently.
"""
from __future__ import annotations

import datetime
from typing import Any


def _safe(value: Any) -> str:
    if value is None:
        return "—"
    return str(value)


def _stale_count(hosts: list[dict], days: int = 30) -> int:
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
    n = 0
    for h in hosts or []:
        last_seen = h.get("last_seen") or ""
        if not last_seen:
            continue
        try:
            ts = datetime.datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=datetime.timezone.utc)
            if ts < cutoff:
                n += 1
        except Exception:
            continue
    return n


def _count_by_severity(rows: list[dict], severity_field: str, *, value: str) -> int:
    return sum(1 for r in rows or [] if (r.get(severity_field) or "").upper() == value.upper())


def _spotlight_severity_count(vulns: list[dict], severity: str) -> int:
    n = 0
    for v in vulns or []:
        sev = ((v.get("cve") or {}).get("severity") or v.get("severity") or "").upper()
        if sev == severity.upper():
            n += 1
    return n


def _qualys_severity5_count(detections: list[dict]) -> int:
    return sum(1 for d in detections or [] if str(d.get("SEVERITY") or "").strip() == "5")


def _iom_severity_count(ioms: list[dict], severity: str) -> int:
    return sum(
        1 for i in ioms or []
        if (i.get("severity") or "").lower() == severity.lower()
    )


def generate_html_report(data: dict, integration_label: str = "default") -> str:
    """Render an HTML posture report.

    Expected ``data`` keys (all optional):
      - hosts, detections, incidents, spotlight_vulns, qualys_detections, host_groups.
    """
    report_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hosts = data.get("hosts") or []
    detections = data.get("detections") or []
    incidents = data.get("incidents") or []
    spotlight = data.get("spotlight_vulns") or []
    qualys_dets = data.get("qualys_detections") or []
    host_groups = data.get("host_groups") or []
    ioms = data.get("ioms") or []

    summary = {
        "hosts_total": len(hosts),
        "stale_hosts": _stale_count(hosts, 30),
        "open_high_crit": sum(
            1 for d in detections
            if (d.get("max_severity_displayname") or d.get("severity_name") or "").lower() in ("high", "critical")
        ),
        "incidents_open": len(incidents),
        "spotlight_critical": _spotlight_severity_count(spotlight, "CRITICAL"),
        "spotlight_high": _spotlight_severity_count(spotlight, "HIGH"),
        "qualys_sev5": _qualys_severity5_count(qualys_dets),
        "host_groups": len(host_groups),
        "ioms_critical": _iom_severity_count(ioms, "Critical"),
        "ioms_high": _iom_severity_count(ioms, "High"),
    }

    def _host_row(h: dict) -> str:
        return (
            "<tr>"
            f"<td>{_safe(h.get('hostname'))}</td>"
            f"<td>{_safe(h.get('os_version') or h.get('os_product_name'))}</td>"
            f"<td>{_safe(h.get('platform_name'))}</td>"
            f"<td>{_safe(h.get('agent_version'))}</td>"
            f"<td>{_safe(h.get('last_seen'))}</td>"
            f"<td>{_safe(h.get('status'))}</td>"
            "</tr>"
        )

    def _detection_row(d: dict) -> str:
        device = d.get("device") or {}
        behaviors = d.get("behaviors") or []
        tactic = behaviors[0].get("tactic") if behaviors else ""
        technique = behaviors[0].get("technique") if behaviors else ""
        return (
            "<tr>"
            f"<td>{_safe(d.get('created_timestamp') or d.get('first_behavior'))}</td>"
            f"<td>{_safe(d.get('max_severity_displayname') or d.get('severity_name'))}</td>"
            f"<td>{_safe(tactic)} / {_safe(technique)}</td>"
            f"<td>{_safe(device.get('hostname'))}</td>"
            f"<td>{_safe(d.get('status'))}</td>"
            "</tr>"
        )

    def _incident_row(i: dict) -> str:
        hosts_ = i.get("hosts") or []
        return (
            "<tr>"
            f"<td>{_safe(i.get('modified_timestamp') or i.get('start'))}</td>"
            f"<td>{_safe(i.get('state'))}</td>"
            f"<td>{len(hosts_)}</td>"
            f"<td>{_safe(', '.join(i.get('tactics') or []))}</td>"
            f"<td>{_safe((i.get('description') or '')[:160])}</td>"
            "</tr>"
        )

    def _spotlight_row(v: dict) -> str:
        cve = v.get("cve") or {}
        host_info = v.get("host_info") or {}
        return (
            "<tr>"
            f"<td>{_safe(cve.get('id'))}</td>"
            f"<td>{_safe(cve.get('cvss_v3_base_score'))}</td>"
            f"<td>{_safe(cve.get('severity'))}</td>"
            f"<td>{_safe(host_info.get('hostname'))}</td>"
            f"<td>{_safe((v.get('apps') or [{}])[0].get('product_name_version'))}</td>"
            f"<td>{_safe(v.get('status'))}</td>"
            "</tr>"
        )

    def _qualys_row(d: dict) -> str:
        return (
            "<tr>"
            f"<td>{_safe(d.get('IP'))}</td>"
            f"<td>{_safe(d.get('QID'))}</td>"
            f"<td>{_safe(d.get('SEVERITY'))}</td>"
            f"<td>{_safe(d.get('FIRST_FOUND_DATETIME'))}</td>"
            f"<td>{_safe(d.get('LAST_FOUND_DATETIME'))}</td>"
            f"<td>{_safe(d.get('STATUS'))}</td>"
            "</tr>"
        )

    def _group_row(g: dict) -> str:
        return (
            "<tr>"
            f"<td>{_safe(g.get('name'))}</td>"
            f"<td>{_safe(g.get('group_type'))}</td>"
            f"<td>{_safe(g.get('member_count'))}</td>"
            f"<td>{_safe(g.get('created_timestamp'))}</td>"
            "</tr>"
        )

    def _iom_row(i: dict) -> str:
        return (
            "<tr>"
            f"<td>{_safe(i.get('cloud_provider'))}</td>"
            f"<td>{_safe(i.get('account_name') or i.get('account_id'))}</td>"
            f"<td>{_safe(i.get('resource_type'))}</td>"
            f"<td>{_safe(i.get('resource_id'))}</td>"
            f"<td>{_safe(i.get('policy_statement') or i.get('policy_id'))}</td>"
            f"<td>{_safe(i.get('severity'))}</td>"
            f"<td>{_safe(i.get('status'))}</td>"
            "</tr>"
        )

    # Sort + cap rows per spec
    sorted_hosts = sorted(hosts, key=lambda h: h.get("last_seen") or "", reverse=True)[:25]
    detections_top = detections[:25]
    incidents_top = incidents[:15]
    spotlight_top = sorted(
        spotlight,
        key=lambda v: float((v.get("cve") or {}).get("cvss_v3_base_score") or 0),
        reverse=True,
    )[:25]
    qualys_top = qualys_dets[:25] if not spotlight else []  # Qualys only when Spotlight unavailable
    groups_top = host_groups[:15]
    # IOMs sorted by severity (Critical > High > Medium > Low > Informational)
    _IOM_SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    ioms_top = sorted(
        ioms,
        key=lambda r: _IOM_SEV.get((r.get("severity") or "").lower(), 5),
    )[:25]

    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Endpoint Security Posture — {_safe(integration_label)}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f4f4; color: #333; }}
        .container {{ width: 80%; margin: 20px auto; background: #fff; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1, h2, h3 {{ color: #333; border-bottom: 2px solid #4CAF50; padding-bottom: 10px; }}
        h1 {{ text-align: center; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 20px; }}
        .summary-item {{ background: #f9f9f9; padding: 15px; border-radius: 5px; border-left: 5px solid #4CAF50; }}
        .summary-item .value {{ font-size: 2em; font-weight: bold; }}
        .critical {{ border-color: #f44336; }}
        .high {{ border-color: #ff9800; }}
        .medium {{ border-color: #ffc107; }}
        .low {{ border-color: #4caf50; }}
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
        th, td {{ padding: 12px; border: 1px solid #ddd; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        .footer {{ text-align: center; margin-top: 20px; font-size: 0.9em; color: #777; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Endpoint Security Posture</h1>
        <p><strong>Integration:</strong> {_safe(integration_label)}</p>
        <p><strong>Report Date:</strong> {report_date}</p>

        <h2>Executive Summary</h2>
        <div class="summary-grid">
            <div class="summary-item"><div>Hosts</div><div class="value">{summary['hosts_total']}</div></div>
            <div class="summary-item"><div>Stale Hosts (>30d)</div><div class="value">{summary['stale_hosts']}</div></div>
            <div class="summary-item high"><div>Open High/Critical Detections</div><div class="value">{summary['open_high_crit']}</div></div>
            <div class="summary-item critical"><div>Open Incidents</div><div class="value">{summary['incidents_open']}</div></div>
            <div class="summary-item critical"><div>Spotlight Critical</div><div class="value">{summary['spotlight_critical']}</div></div>
            <div class="summary-item high"><div>Spotlight High</div><div class="value">{summary['spotlight_high']}</div></div>
            <div class="summary-item critical"><div>Qualys Severity 5</div><div class="value">{summary['qualys_sev5']}</div></div>
            <div class="summary-item critical"><div>IOMs Critical</div><div class="value">{summary['ioms_critical']}</div></div>
            <div class="summary-item high"><div>IOMs High</div><div class="value">{summary['ioms_high']}</div></div>
            <div class="summary-item"><div>Host Groups</div><div class="value">{summary['host_groups']}</div></div>
        </div>

        <h2>Hosts (top 25 by last_seen)</h2>
        {"<table><tr><th>Hostname</th><th>OS</th><th>Platform</th><th>Sensor</th><th>Last seen</th><th>Status</th></tr>" + "".join(_host_row(h) for h in sorted_hosts) + "</table>" if sorted_hosts else "<p>No hosts returned.</p>"}

        <h2>Recent Detections (top 25)</h2>
        {"<table><tr><th>Created</th><th>Severity</th><th>Tactic / Technique</th><th>Hostname</th><th>Status</th></tr>" + "".join(_detection_row(d) for d in detections_top) + "</table>" if detections_top else "<p>No recent detections.</p>"}

        <h2>Recent Incidents (top 15)</h2>
        {"<table><tr><th>Modified</th><th>State</th><th>Hosts</th><th>Tactics</th><th>Description</th></tr>" + "".join(_incident_row(i) for i in incidents_top) + "</table>" if incidents_top else "<p>No recent incidents.</p>"}

        <h2>Top Spotlight Vulnerabilities (top 25 by CVSS)</h2>
        {"<table><tr><th>CVE</th><th>CVSS</th><th>Severity</th><th>Hostname</th><th>Product</th><th>Status</th></tr>" + "".join(_spotlight_row(v) for v in spotlight_top) + "</table>" if spotlight_top else "<p>No Spotlight vulnerabilities returned.</p>"}

        {("<h2>Qualys Host Detections (severity 5/4)</h2><table><tr><th>IP</th><th>QID</th><th>Severity</th><th>First Found</th><th>Last Found</th><th>Status</th></tr>" + "".join(_qualys_row(d) for d in qualys_top) + "</table>") if qualys_top else ""}

        <h2>Cloud Misconfigurations — Falcon IOMs (top 25 by severity)</h2>
        {"<table><tr><th>Cloud</th><th>Account</th><th>Resource Type</th><th>Resource</th><th>Policy</th><th>Severity</th><th>Status</th></tr>" + "".join(_iom_row(i) for i in ioms_top) + "</table>" if ioms_top else "<p>No open Falcon Cloud Security IOMs.</p>"}

        <h2>Host Groups (top 15)</h2>
        {"<table><tr><th>Name</th><th>Type</th><th>Members</th><th>Created</th></tr>" + "".join(_group_row(g) for g in groups_top) + "</table>" if groups_top else "<p>No host groups defined.</p>"}

        <div class="footer">
            <p>Generated by Security Mind AI</p>
        </div>
    </div>
</body>
</html>
"""
