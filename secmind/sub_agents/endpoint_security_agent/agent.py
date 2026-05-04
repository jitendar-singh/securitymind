"""Endpoint Security sub-agent — CrowdStrike Falcon + Qualys VM.

All list/get tools are read-only and route through ``cache.cached(...)`` so
repeated calls within the TTL hit the local SQLite cache instead of the vendor
API. Aggregating tools (``correlate_*``, ``generate_endpoint_report``) skip the
wrapper since they themselves combine cached calls.
"""
from __future__ import annotations

import logging
from typing import Optional

from google.adk.agents import Agent

from secmind.integration_store import get_store
from secmind.user_context import current_user_id

import os
import re
from datetime import datetime

from . import cache as _cache
from . import correlate as _corr
from .clients import FalconClient, QualysClient
from .instruction_builder import (
    build_agent_instructions,
    build_agent_name,
    build_short_description,
)
from .report_generator import generate_html_report

logger = logging.getLogger(__name__)


def _first_active(provider: str) -> Optional[dict]:
    """Return the first active integration record for ``provider`` (scoped to
    the current request's user) or None if there is no user in context or no
    matching active integration."""
    uid = current_user_id()
    if uid is None:
        return None
    for rec in get_store().iter_active(uid):
        if rec["provider"] == provider:
            return rec
    return None


def _ok(message: str, data) -> dict:
    return {"status": "success", "message": message, "data": data}


def _err(message: str) -> dict:
    return {"status": "error", "message": message}


_NO_FALCON = "No active CrowdStrike integration. Configure one on the Integrations page."
_NO_QUALYS = "No active Qualys integration. Configure one on the Integrations page."


# ---------------------------------------------------------------------------
# CrowdStrike — base list/get tools (cached)
# ---------------------------------------------------------------------------


def crowdstrike_list_hosts(filter: str = "", limit: int = 100) -> dict:
    """List CrowdStrike Falcon hosts. ``filter`` is FQL (Falcon Query Language)."""
    rec = _first_active("crowdstrike")
    if rec is None:
        return _err(_NO_FALCON)

    def _do() -> dict:
        try:
            rows = FalconClient(rec["config"]).list_hosts(filter_str=filter, limit=limit)
            return _ok(f"Returned {len(rows)} host(s)", {"hosts": rows})
        except Exception as e:
            logger.exception("crowdstrike_list_hosts failed")
            return _err(str(e))

    return _cache.cached(
        "crowdstrike", rec["name"], "crowdstrike_list_hosts",
        {"filter": filter, "limit": limit}, _do,
    )


def crowdstrike_get_host(device_id: str) -> dict:
    """Get full details for a single Falcon device by device_id."""
    if not device_id:
        return _err("device_id is required")
    rec = _first_active("crowdstrike")
    if rec is None:
        return _err(_NO_FALCON)

    def _do() -> dict:
        try:
            rows = FalconClient(rec["config"]).get_hosts([device_id])
            if not rows:
                return _err(f"Host {device_id} not found")
            return _ok(f"Loaded host {device_id}", {"host": rows[0]})
        except Exception as e:
            logger.exception("crowdstrike_get_host failed")
            return _err(str(e))

    return _cache.cached(
        "crowdstrike", rec["name"], "crowdstrike_get_host",
        {"device_id": device_id}, _do,
    )


def crowdstrike_list_detections(filter: str = "", limit: int = 100) -> dict:
    """List recent Falcon detections (newest first). ``filter`` is FQL."""
    rec = _first_active("crowdstrike")
    if rec is None:
        return _err(_NO_FALCON)

    def _do() -> dict:
        try:
            rows = FalconClient(rec["config"]).list_detections(filter_str=filter, limit=limit)
            return _ok(f"Returned {len(rows)} detection(s)", {"detections": rows})
        except Exception as e:
            logger.exception("crowdstrike_list_detections failed")
            return _err(str(e))

    return _cache.cached(
        "crowdstrike", rec["name"], "crowdstrike_list_detections",
        {"filter": filter, "limit": limit}, _do,
    )


def crowdstrike_get_detection(detection_id: str) -> dict:
    """Get details for a single Falcon detection by detection_id."""
    if not detection_id:
        return _err("detection_id is required")
    rec = _first_active("crowdstrike")
    if rec is None:
        return _err(_NO_FALCON)

    def _do() -> dict:
        try:
            rows = FalconClient(rec["config"]).get_detections([detection_id])
            if not rows:
                return _err(f"Detection {detection_id} not found")
            return _ok(f"Loaded detection {detection_id}", {"detection": rows[0]})
        except Exception as e:
            logger.exception("crowdstrike_get_detection failed")
            return _err(str(e))

    return _cache.cached(
        "crowdstrike", rec["name"], "crowdstrike_get_detection",
        {"detection_id": detection_id}, _do,
    )


def crowdstrike_list_incidents(filter: str = "", limit: int = 50) -> dict:
    """List recent Falcon incidents (newest first). ``filter`` is FQL."""
    rec = _first_active("crowdstrike")
    if rec is None:
        return _err(_NO_FALCON)

    def _do() -> dict:
        try:
            rows = FalconClient(rec["config"]).list_incidents(filter_str=filter, limit=limit)
            return _ok(f"Returned {len(rows)} incident(s)", {"incidents": rows})
        except Exception as e:
            logger.exception("crowdstrike_list_incidents failed")
            return _err(str(e))

    return _cache.cached(
        "crowdstrike", rec["name"], "crowdstrike_list_incidents",
        {"filter": filter, "limit": limit}, _do,
    )


# ---------------------------------------------------------------------------
# Qualys — base list tools (cached)
# ---------------------------------------------------------------------------


def qualys_list_assets(ips: str = "", limit: int = 100) -> dict:
    """List Qualys host assets. ``ips`` is optional comma-separated filter."""
    rec = _first_active("qualys")
    if rec is None:
        return _err(_NO_QUALYS)

    def _do() -> dict:
        try:
            rows = QualysClient(rec["config"]).list_assets(ips=ips, limit=limit)
            return _ok(f"Returned {len(rows)} asset(s)", {"assets": rows})
        except Exception as e:
            logger.exception("qualys_list_assets failed")
            return _err(str(e))

    return _cache.cached(
        "qualys", rec["name"], "qualys_list_assets",
        {"ips": ips, "limit": limit}, _do,
    )


def qualys_list_host_detections(ips: str = "", severities: str = "", limit: int = 100) -> dict:
    """List Qualys vulnerability detections per host.

    Args:
        ips: Optional comma-separated IPs/CIDRs to scope.
        severities: Optional comma-separated severities (1-5; 5 = critical).
        limit: Max rows.
    """
    rec = _first_active("qualys")
    if rec is None:
        return _err(_NO_QUALYS)

    def _do() -> dict:
        try:
            rows = QualysClient(rec["config"]).list_host_detections(
                ips=ips, severities=severities, limit=limit
            )
            return _ok(f"Returned {len(rows)} host detection record(s)", {"detections": rows})
        except Exception as e:
            logger.exception("qualys_list_host_detections failed")
            return _err(str(e))

    return _cache.cached(
        "qualys", rec["name"], "qualys_list_host_detections",
        {"ips": ips, "severities": severities, "limit": limit}, _do,
    )


def qualys_list_scans(state: str = "", limit: int = 50) -> dict:
    """List Qualys scans. ``state`` optional ("Running", "Finished", etc.)."""
    rec = _first_active("qualys")
    if rec is None:
        return _err(_NO_QUALYS)

    def _do() -> dict:
        try:
            rows = QualysClient(rec["config"]).list_scans(state=state, limit=limit)
            return _ok(f"Returned {len(rows)} scan(s)", {"scans": rows})
        except Exception as e:
            logger.exception("qualys_list_scans failed")
            return _err(str(e))

    return _cache.cached(
        "qualys", rec["name"], "qualys_list_scans",
        {"state": state, "limit": limit}, _do,
    )


# ---------------------------------------------------------------------------
# T1 — Vulnerability depth: Spotlight + Qualys KB + cross-vendor join
# ---------------------------------------------------------------------------


def crowdstrike_list_spotlight_vulns(filter: str = "", limit: int = 100) -> dict:
    """List CrowdStrike Spotlight host-vuln rows. ``filter`` is FQL.

    Common filters: ``host_info.hostname:'web-01'``, ``cve.severity:'CRITICAL'``,
    ``status:'open'``, ``updated_timestamp:>'2025-01-01'``.
    """
    rec = _first_active("crowdstrike")
    if rec is None:
        return _err(_NO_FALCON)

    def _do() -> dict:
        try:
            rows = FalconClient(rec["config"]).list_spotlight_vulns(filter_str=filter, limit=limit)
            return _ok(f"Returned {len(rows)} Spotlight vuln(s)", {"vulns": rows})
        except Exception as e:
            logger.exception("crowdstrike_list_spotlight_vulns failed")
            return _err(str(e))

    return _cache.cached(
        "crowdstrike", rec["name"], "crowdstrike_list_spotlight_vulns",
        {"filter": filter, "limit": limit}, _do,
    )


def crowdstrike_get_spotlight_vuln(vuln_id: str) -> dict:
    """Get a single Spotlight vulnerability record by id."""
    if not vuln_id:
        return _err("vuln_id is required")
    rec = _first_active("crowdstrike")
    if rec is None:
        return _err(_NO_FALCON)

    def _do() -> dict:
        try:
            rows = FalconClient(rec["config"]).get_spotlight_vulnerabilities([vuln_id])
            if not rows:
                return _err(f"Spotlight vuln {vuln_id} not found")
            return _ok(f"Loaded Spotlight vuln {vuln_id}", {"vuln": rows[0]})
        except Exception as e:
            logger.exception("crowdstrike_get_spotlight_vuln failed")
            return _err(str(e))

    return _cache.cached(
        "crowdstrike", rec["name"], "crowdstrike_get_spotlight_vuln",
        {"vuln_id": vuln_id}, _do,
    )


def qualys_get_kb_vuln(qid: str) -> dict:
    """Look up a Qualys Knowledge Base entry by QID.

    Use after ``qualys_list_host_detections`` returns a QID you want to explain.
    Returns title, severity, CVE list, fix, references, etc.
    """
    if not qid:
        return _err("qid is required")
    rec = _first_active("qualys")
    if rec is None:
        return _err(_NO_QUALYS)

    def _do() -> dict:
        try:
            row = QualysClient(rec["config"]).get_kb_vuln(qid)
            if row is None:
                return _err(f"QID {qid} not found in Qualys KB")
            return _ok(f"Loaded Qualys KB QID {qid}", {"kb": row})
        except Exception as e:
            logger.exception("qualys_get_kb_vuln failed")
            return _err(str(e))

    return _cache.cached(
        "qualys", rec["name"], "qualys_get_kb_vuln",
        {"qid": qid}, _do,
    )


def correlate_host_vulns(hostname_or_ip: str) -> dict:
    """Cross-vendor: pull host vulnerabilities from Falcon Spotlight AND Qualys.

    Returns:
      - ``falcon.vulns`` — Spotlight rows for the host
      - ``qualys.detections`` — Qualys host detection rows (only when input is an IP;
        Qualys VM doesn't accept hostname filters in this endpoint)
      - ``summary`` — severity counts from Falcon plus the CVE intersection.
        CVE intersection is best-effort — Qualys list responses don't always carry
        CVE refs; use ``qualys_get_kb_vuln(qid)`` per QID for full enrichment.
    """
    if not hostname_or_ip or not hostname_or_ip.strip():
        return _err("hostname_or_ip is required")
    target = hostname_or_ip.strip()

    falcon_filter = _corr.falcon_filter_for(target)
    falcon_vulns: list[dict] = []
    falcon_msg = ""
    falcon_result = crowdstrike_list_spotlight_vulns(filter=falcon_filter, limit=200)
    if falcon_result.get("status") == "success":
        falcon_vulns = falcon_result.get("data", {}).get("vulns", [])
    else:
        falcon_msg = falcon_result.get("message", "")

    qualys_dets: list[dict] = []
    qualys_msg = ""
    if _corr.is_ip(target):
        qualys_result = qualys_list_host_detections(ips=target, limit=200)
        if qualys_result.get("status") == "success":
            qualys_dets = qualys_result.get("data", {}).get("detections", [])
        else:
            qualys_msg = qualys_result.get("message", "")

    falcon_cves = _corr.cves_from_falcon_spotlight(falcon_vulns)
    sev = _corr.severity_counts_from_falcon_spotlight(falcon_vulns)

    return _ok(
        (
            f"Falcon: {len(falcon_vulns)} Spotlight vuln(s); "
            f"Qualys: {len(qualys_dets)} host record(s)"
            + (f"; falcon error: {falcon_msg}" if falcon_msg else "")
            + (f"; qualys error: {qualys_msg}" if qualys_msg else "")
        ),
        {
            "input": target,
            "is_ip": _corr.is_ip(target),
            "falcon": {"vulns": falcon_vulns, "errors": falcon_msg or None},
            "qualys": {"detections": qualys_dets, "errors": qualys_msg or None},
            "summary": {
                "falcon_severity_counts": sev,
                "falcon_cves": sorted(falcon_cves),
                "common_cves": [],  # populated only if a future detector pulls Qualys CVEs
            },
        },
    )


# ---------------------------------------------------------------------------
# T4 — Cross-vendor host correlation
# ---------------------------------------------------------------------------


def _gce_match_from_memory(target: str) -> Optional[dict]:
    """Best-effort lookup of a GCE instance matching ``target`` across cached
    memory tables. Returns ``{instance, project_id}`` or None.

    Uses ``MemoryManager.get_gce_instances`` if any project's data was
    populated by ``gcp_workload_security_agent.checks.list_gce_instances``.
    Reads cache only — never makes a live API call.
    """
    try:
        from secmind.memory import get_memory_manager

        mem = get_memory_manager()
        # We don't know which projects have been listed, so iterate the
        # gce_instances table directly.
        rows = mem.sqlite_conn.execute(
            "SELECT project_id, instances_json FROM gce_instances"
        ).fetchall()
    except Exception:
        logger.exception("_gce_match_from_memory: failed to query memory")
        return None

    short, fqdn = _corr.normalize_hostname(target)
    candidates = {short}
    if fqdn:
        candidates.add(fqdn)

    is_target_ip = _corr.is_ip(target)
    import json as _json

    for row in rows:
        try:
            payload = _json.loads(row["instances_json"])
        except Exception:
            continue
        instances = (payload or {}).get("data", {}).get("instances", [])
        if not isinstance(instances, list):
            continue
        for inst in instances:
            # ``instances`` from gcp_workload_security_agent.checks is a list
            # of bare names (strings) by default; if upstream evolves to dicts
            # we handle both.
            name = inst if isinstance(inst, str) else (inst or {}).get("name", "")
            if not name:
                continue
            short_name = name.split(".")[0].lower()
            if not is_target_ip and (short_name in candidates or name.lower() in candidates):
                return {"instance": inst, "project_id": row["project_id"]}
    return None


def correlate_host(hostname_or_ip: str) -> dict:
    """Unified host card joining Falcon device + Qualys asset + (best-effort) GCE inventory.

    Args:
        hostname_or_ip: Either a hostname (FQDN or short) or an IPv4/IPv6 address.

    Returns:
        ``{input, hostname, ips, falcon: {host}, qualys: {asset}, gce: {instance, project_id}}``.
        Each backend block is ``None`` if no match was found or that integration
        isn't configured. GCE is read from MemoryManager cache only — it does NOT
        make a live GCP call.
    """
    if not hostname_or_ip or not hostname_or_ip.strip():
        return _err("hostname_or_ip is required")
    target = hostname_or_ip.strip()

    # Falcon
    falcon_filter = _corr.falcon_filter_for(target)
    falcon_host: Optional[dict] = None
    falcon_msg = ""
    if falcon_filter:
        f_result = crowdstrike_list_hosts(filter=falcon_filter, limit=5)
        if f_result.get("status") == "success":
            hosts = f_result.get("data", {}).get("hosts", [])
            if hosts:
                falcon_host = hosts[0]
        else:
            falcon_msg = f_result.get("message", "")

    # Qualys — only IP filter is supported by /asset/host/
    qualys_asset: Optional[dict] = None
    qualys_msg = ""
    if _corr.is_ip(target):
        q_result = qualys_list_assets(ips=target, limit=5)
        if q_result.get("status") == "success":
            assets = q_result.get("data", {}).get("assets", [])
            if assets:
                qualys_asset = assets[0]
        else:
            qualys_msg = q_result.get("message", "")

    # GCE — from MemoryManager cache only (read-only join)
    gce = _gce_match_from_memory(target)

    # Build hostname/IP best-guess from whichever side returned data
    hostname = ""
    ips: list[str] = []
    if falcon_host:
        hostname = falcon_host.get("hostname") or hostname
        # Falcon device payload includes local_ip / external_ip
        for f in ("local_ip", "external_ip"):
            v = falcon_host.get(f)
            if v and v not in ips:
                ips.append(v)
    if qualys_asset:
        hostname = hostname or qualys_asset.get("DNS") or qualys_asset.get("NETBIOS") or ""
        ip_val = qualys_asset.get("IP")
        if ip_val and ip_val not in ips:
            ips.append(ip_val)
    if not hostname and not _corr.is_ip(target):
        hostname = target

    return _ok(
        (
            f"Falcon: {'match' if falcon_host else 'no match'}; "
            f"Qualys: {'match' if qualys_asset else 'no match' if _corr.is_ip(target) else 'skipped (hostname-only input)'}; "
            f"GCE: {'match' if gce else 'no match'}"
            + (f"; falcon error: {falcon_msg}" if falcon_msg else "")
            + (f"; qualys error: {qualys_msg}" if qualys_msg else "")
        ),
        {
            "input": target,
            "hostname": hostname,
            "ips": ips,
            "falcon": {"host": falcon_host},
            "qualys": {"asset": qualys_asset},
            "gce": gce or {"instance": None, "project_id": None},
        },
    )


# ---------------------------------------------------------------------------
# T2 — Threat hunting & IR: IOC search, audit log, host groups
# ---------------------------------------------------------------------------


def crowdstrike_list_iocs(filter: str = "", limit: int = 100) -> dict:
    """List Falcon Custom IOCs. Filter examples: ``type:'sha256'``, ``severity:'high'``,
    ``value:'1.2.3.4'``."""
    rec = _first_active("crowdstrike")
    if rec is None:
        return _err(_NO_FALCON)

    def _do() -> dict:
        try:
            rows = FalconClient(rec["config"]).list_iocs(filter_str=filter, limit=limit)
            return _ok(f"Returned {len(rows)} IOC(s)", {"iocs": rows})
        except Exception as e:
            logger.exception("crowdstrike_list_iocs failed")
            return _err(str(e))

    return _cache.cached(
        "crowdstrike", rec["name"], "crowdstrike_list_iocs",
        {"filter": filter, "limit": limit}, _do,
    )


def crowdstrike_get_ioc(ioc_id: str) -> dict:
    """Get full details for a single Falcon Custom IOC by id."""
    if not ioc_id:
        return _err("ioc_id is required")
    rec = _first_active("crowdstrike")
    if rec is None:
        return _err(_NO_FALCON)

    def _do() -> dict:
        try:
            rows = FalconClient(rec["config"]).get_iocs([ioc_id])
            if not rows:
                return _err(f"IOC {ioc_id} not found")
            return _ok(f"Loaded IOC {ioc_id}", {"ioc": rows[0]})
        except Exception as e:
            logger.exception("crowdstrike_get_ioc failed")
            return _err(str(e))

    return _cache.cached(
        "crowdstrike", rec["name"], "crowdstrike_get_ioc",
        {"ioc_id": ioc_id}, _do,
    )


def crowdstrike_list_audit_events(filter: str = "", limit: int = 100) -> dict:
    """List Falcon platform audit events. Filter examples:
    ``service_name:'Detections'``, ``action_target_name:'user@example.com'``,
    ``time:>'2025-01-01'``."""
    rec = _first_active("crowdstrike")
    if rec is None:
        return _err(_NO_FALCON)

    def _do() -> dict:
        try:
            rows = FalconClient(rec["config"]).list_audit_events(filter_str=filter, limit=limit)
            return _ok(f"Returned {len(rows)} audit event(s)", {"events": rows})
        except Exception as e:
            logger.exception("crowdstrike_list_audit_events failed")
            return _err(str(e))

    return _cache.cached(
        "crowdstrike", rec["name"], "crowdstrike_list_audit_events",
        {"filter": filter, "limit": limit}, _do,
    )


def crowdstrike_list_ioms(filter: str = "", limit: int = 100) -> dict:
    """List Falcon Cloud Security Indicators of Misconfiguration (IOMs).

    IOMs are cloud-account configuration findings (e.g. ``S3 bucket public``,
    ``IAM user without MFA``). Filter examples:
    ``cloud_provider:'aws'``, ``severity:'High'``, ``status:'open'``,
    ``policy_id:'<id>'``, ``account_name:'prod'``.
    """
    rec = _first_active("crowdstrike")
    if rec is None:
        return _err(_NO_FALCON)

    def _do() -> dict:
        try:
            rows = FalconClient(rec["config"]).list_ioms(filter_str=filter, limit=limit)
            return _ok(f"Returned {len(rows)} IOM finding(s)", {"ioms": rows})
        except Exception as e:
            logger.exception("crowdstrike_list_ioms failed")
            return _err(str(e))

    return _cache.cached(
        "crowdstrike", rec["name"], "crowdstrike_list_ioms",
        {"filter": filter, "limit": limit}, _do,
    )


def crowdstrike_get_iom(iom_id: str) -> dict:
    """Get full details for a single Falcon Cloud Security IOM by id."""
    if not iom_id:
        return _err("iom_id is required")
    rec = _first_active("crowdstrike")
    if rec is None:
        return _err(_NO_FALCON)

    def _do() -> dict:
        try:
            rows = FalconClient(rec["config"]).get_ioms([iom_id])
            if not rows:
                return _err(f"IOM {iom_id} not found")
            return _ok(f"Loaded IOM {iom_id}", {"iom": rows[0]})
        except Exception as e:
            logger.exception("crowdstrike_get_iom failed")
            return _err(str(e))

    return _cache.cached(
        "crowdstrike", rec["name"], "crowdstrike_get_iom",
        {"iom_id": iom_id}, _do,
    )


def crowdstrike_list_host_groups(filter: str = "", limit: int = 100) -> dict:
    """List Falcon host groups (managed device groupings). Filter examples:
    ``name:*'prod'*``, ``group_type:'static'``."""
    rec = _first_active("crowdstrike")
    if rec is None:
        return _err(_NO_FALCON)

    def _do() -> dict:
        try:
            rows = FalconClient(rec["config"]).list_host_groups(filter_str=filter, limit=limit)
            return _ok(f"Returned {len(rows)} host group(s)", {"groups": rows})
        except Exception as e:
            logger.exception("crowdstrike_list_host_groups failed")
            return _err(str(e))

    return _cache.cached(
        "crowdstrike", rec["name"], "crowdstrike_list_host_groups",
        {"filter": filter, "limit": limit}, _do,
    )


# ---------------------------------------------------------------------------
# T3 — Endpoint posture HTML report
# ---------------------------------------------------------------------------


_FILENAME_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _filename_token(s: str) -> str:
    """Sanitize an integration name for inclusion in a report filename."""
    return _FILENAME_SAFE.sub("-", (s or "default").strip())[:40] or "default"


def generate_endpoint_report() -> dict:
    """Generate an HTML endpoint security posture report and save it to ``reports/``.

    Aggregates hosts, recent detections, incidents, Spotlight vulnerabilities,
    Qualys host detections (fallback when Spotlight is empty), and host groups.
    All inputs come from the cached list tools, so a same-day re-run is cheap.

    Returns ``{status, message}``. The user finds the report on the Reports page;
    the message intentionally does NOT include the file path.
    """
    cs_rec = _first_active("crowdstrike")
    q_rec = _first_active("qualys")
    if cs_rec is None and q_rec is None:
        return _err(
            "No active CrowdStrike or Qualys integration. Configure at least one on the Integrations page."
        )
    integration_label = (cs_rec or q_rec)["name"]

    data: dict = {}

    # CrowdStrike
    if cs_rec is not None:
        hosts = crowdstrike_list_hosts(filter="", limit=100)
        if hosts.get("status") == "success":
            data["hosts"] = hosts.get("data", {}).get("hosts", [])
        dets = crowdstrike_list_detections(filter="", limit=50)
        if dets.get("status") == "success":
            data["detections"] = dets.get("data", {}).get("detections", [])
        incs = crowdstrike_list_incidents(filter="", limit=25)
        if incs.get("status") == "success":
            data["incidents"] = incs.get("data", {}).get("incidents", [])
        spot = crowdstrike_list_spotlight_vulns(filter="status:'open'", limit=100)
        if spot.get("status") == "success":
            data["spotlight_vulns"] = spot.get("data", {}).get("vulns", [])
        groups = crowdstrike_list_host_groups(filter="", limit=50)
        if groups.get("status") == "success":
            data["host_groups"] = groups.get("data", {}).get("groups", [])
        ioms = crowdstrike_list_ioms(filter="status:'open'", limit=100)
        if ioms.get("status") == "success":
            data["ioms"] = ioms.get("data", {}).get("ioms", [])

    # Qualys — only as fallback when Spotlight returned nothing
    if q_rec is not None and not data.get("spotlight_vulns"):
        qd = qualys_list_host_detections(ips="", severities="4,5", limit=100)
        if qd.get("status") == "success":
            data["qualys_detections"] = qd.get("data", {}).get("detections", [])

    try:
        html = generate_html_report(data, integration_label=integration_label)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = f"endpoint_security_report-{_filename_token(integration_label)}-{ts}.html"
        reports_dir = os.path.abspath(os.environ.get("REPORTS_DIR", "reports"))
        os.makedirs(reports_dir, exist_ok=True)
        path = os.path.join(reports_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        logger.info("Endpoint security report saved to %s", path)
        # Intentionally do NOT include the path in the user-facing message.
        return {
            "status": "success",
            "message": "The endpoint security report has been generated.",
        }
    except Exception as e:
        logger.exception("generate_endpoint_report failed")
        return _err(f"Failed to generate report: {e}")


# ---------------------------------------------------------------------------
# Cache control
# ---------------------------------------------------------------------------


def clear_endpoint_cache() -> dict:
    """Clear ALL cached endpoint-security results.

    Run only when the user explicitly asks for fresh data; otherwise rely on the
    15-minute TTL.
    """
    try:
        n = _cache.clear_all()
        return _ok(f"Cleared {n} cached entries", {"cleared": n})
    except Exception as e:
        logger.exception("clear_endpoint_cache failed")
        return _err(str(e))


AGENT_TOOLS = [
    # CrowdStrike base
    crowdstrike_list_hosts,
    crowdstrike_get_host,
    crowdstrike_list_detections,
    crowdstrike_get_detection,
    crowdstrike_list_incidents,
    # Qualys base
    qualys_list_assets,
    qualys_list_host_detections,
    qualys_list_scans,
    # T1 — Vulnerability depth
    crowdstrike_list_spotlight_vulns,
    crowdstrike_get_spotlight_vuln,
    qualys_get_kb_vuln,
    correlate_host_vulns,
    # T2 — Threat hunting & IR
    crowdstrike_list_iocs,
    crowdstrike_get_ioc,
    crowdstrike_list_audit_events,
    crowdstrike_list_ioms,
    crowdstrike_get_iom,
    crowdstrike_list_host_groups,
    # T4 — Cross-vendor correlation
    correlate_host,
    # T3 — HTML posture report
    generate_endpoint_report,
    # Cache control
    clear_endpoint_cache,
]


endpoint_security_agent = Agent(
    name=build_agent_name(),
    model="gemini-2.5-pro",
    description=build_short_description(),
    instruction=build_agent_instructions(),
    tools=AGENT_TOOLS,
)


__all__ = ["endpoint_security_agent", "AGENT_TOOLS"]
