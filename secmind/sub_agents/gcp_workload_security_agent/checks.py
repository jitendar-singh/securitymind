"""
Framework-free GCP workload checks.

Pure ``(project_id, client=None) -> dict`` functions returning
``{"status", "message", "data"}``. Imported both by the workload Agent's
tool wrappers (LLM-invoked) and by ``cloud_compliance_agent.generate_compliance_report``
(programmatic aggregator) so analysis logic lives in one place.

Each function caches via the project-wide ``MemoryManager`` so duplicate calls
are cheap. All calls are read-only against GCP.
"""
from __future__ import annotations

import logging
from typing import Optional

from secmind.memory import get_memory_manager
from secmind.memory_manager import MemoryManager

from .clients import GcpWorkloadClient

logger = logging.getLogger(__name__)


def _memory() -> MemoryManager:
    # Resolves the current user's MemoryManager (or the legacy shared one
    # when called outside a /chat request, e.g. from the cloud_compliance
    # programmatic aggregator at startup).
    return get_memory_manager()


def _ok(message: str, data: dict) -> dict:
    return {"status": "success", "message": message, "data": data}


def _err(message: str) -> dict:
    return {"status": "error", "message": message}


def _client(project_id: str, client: Optional[GcpWorkloadClient]) -> GcpWorkloadClient:
    return client or GcpWorkloadClient(project_id)


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------


def list_gce_instances(project_id: str, client: Optional[GcpWorkloadClient] = None) -> dict:
    cached = _memory().get_gce_instances(project_id)
    if cached and isinstance(cached, dict) and cached.get("status") == "success":
        return {**cached, "message": f"(cached) {cached.get('message', '')}"}
    try:
        raw = _client(project_id, client).list_gce_instances()
        names = [i.name for i in raw]
        result = _ok(f"Found {len(names)} GCE instances in {project_id}", {"instances": names})
        _memory().add_gce_instances(project_id, result)
        return result
    except Exception as e:
        logger.exception("list_gce_instances failed")
        return _err(str(e))


def list_gke_clusters(project_id: str, client: Optional[GcpWorkloadClient] = None) -> dict:
    cached = _memory().get_gke_clusters(project_id)
    if cached and isinstance(cached, dict) and cached.get("status") == "success":
        return {**cached, "message": f"(cached) {cached.get('message', '')}"}
    try:
        raw = _client(project_id, client).list_gke_clusters()
        clusters = [
            {
                "name": c.name,
                "location": c.location,
                "status": c.status.name,
                "current_master_version": c.current_master_version,
                "private_cluster": c.private_cluster_config.enable_private_nodes,
                "datapath_provider": c.network_config.datapath_provider.name,
                "network": c.network.split("/")[-1],
            }
            for c in raw
        ]
        result = _ok(f"Found {len(clusters)} GKE clusters in {project_id}", {"clusters": clusters})
        _memory().add_gke_clusters(project_id, result)
        return result
    except Exception as e:
        logger.exception("list_gke_clusters failed")
        return _err(str(e))


def list_cloud_run_services(project_id: str, client: Optional[GcpWorkloadClient] = None) -> dict:
    cached = _memory().get_cloud_run_services(project_id)
    if cached and isinstance(cached, dict) and cached.get("status") == "success":
        return {**cached, "message": f"(cached) {cached.get('message', '')}"}
    try:
        raw = _client(project_id, client).list_cloud_run_services()
        services = [
            {
                "name": s.name.split("/")[-1],
                "uri": s.uri,
                "creator": s.creator,
                "last_modifier": s.last_modifier,
                "ingress": s.ingress.name,
                "launch_stage": s.launch_stage.name,
            }
            for s in raw
        ]
        result = _ok(
            f"Found {len(services)} Cloud Run services in {project_id}",
            {"services": services},
        )
        _memory().add_cloud_run_services(project_id, result)
        return result
    except Exception as e:
        logger.exception("list_cloud_run_services failed")
        return _err(str(e))


def list_cloud_functions(project_id: str, client: Optional[GcpWorkloadClient] = None) -> dict:
    cached = _memory().get_cloud_functions(project_id)
    if cached and isinstance(cached, dict) and cached.get("status") == "success":
        return {**cached, "message": f"(cached) {cached.get('message', '')}"}
    try:
        raw = _client(project_id, client).list_cloud_functions()
        functions = [
            {
                "name": f.name.split("/")[-1],
                "state": f.state.name,
                "runtime": f.service_config.runtime,
                "environment": f.environment.name,
                "https_trigger_url": f.service_config.uri,
                "service_account": f.service_config.service_account,
            }
            for f in raw
        ]
        result = _ok(
            f"Found {len(functions)} Cloud Functions in {project_id}",
            {"functions": functions},
        )
        _memory().add_cloud_functions(project_id, result)
        return result
    except Exception as e:
        logger.exception("list_cloud_functions failed")
        return _err(str(e))


def _serialize_firewall_rule(r) -> dict:
    return {
        "name": r.name,
        "description": r.description,
        "network": r.network.split("/")[-1],
        "direction": r.direction,
        "priority": r.priority,
        "source_ranges": list(r.source_ranges),
        "destination_ranges": list(r.destination_ranges),
        "allowed": [{"ip_protocol": a.i_p_protocol, "ports": list(a.ports or [])} for a in r.allowed],
        "denied": [{"ip_protocol": d.i_p_protocol, "ports": list(d.ports or [])} for d in r.denied],
        "disabled": r.disabled,
        "target_tags": list(getattr(r, "target_tags", []) or []),
    }


def list_firewall_rules(project_id: str, client: Optional[GcpWorkloadClient] = None) -> dict:
    cached = _memory().get_firewall_rules(project_id)
    if cached and isinstance(cached, dict) and cached.get("status") == "success":
        return {**cached, "message": f"(cached) {cached.get('message', '')}"}
    try:
        raw = _client(project_id, client).list_firewall_rules()
        rules = [_serialize_firewall_rule(r) for r in raw]
        result = _ok(
            f"Found {len(rules)} firewall rules in {project_id}",
            {"rules": rules},
        )
        _memory().add_firewall_rules(project_id, result)
        return result
    except Exception as e:
        logger.exception("list_firewall_rules failed")
        return _err(str(e))


def get_iam_policy(project_id: str, client: Optional[GcpWorkloadClient] = None) -> dict:
    cached = _memory().get_iam_policy(project_id)
    if cached and isinstance(cached, dict) and cached.get("status") == "success":
        return {**cached, "message": f"(cached) {cached.get('message', '')}"}
    try:
        raw = _client(project_id, client).get_iam_policy()
        bindings = [{"role": b.role, "members": list(b.members)} for b in raw.bindings]
        result = _ok(
            f"Retrieved IAM policy for {project_id}",
            {"version": raw.version, "bindings": bindings},
        )
        _memory().add_iam_policy(project_id, result)
        return result
    except Exception as e:
        logger.exception("get_iam_policy failed")
        return _err(str(e))


def get_gce_instance_details(
    project_id: str,
    instance_name: str,
    zone: str,
    client: Optional[GcpWorkloadClient] = None,
) -> dict:
    cached = _memory().get_gce_instance_details(project_id, instance_name, zone)
    if cached and isinstance(cached, dict) and cached.get("status") == "success":
        return {**cached, "message": f"(cached) {cached.get('message', '')}"}
    try:
        gcp = _client(project_id, client)
        inst = gcp.get_gce_instance_details(instance=instance_name, zone=zone)

        service_accounts = [
            {"email": sa.email, "scopes": list(sa.scopes)}
            for sa in inst.service_accounts
        ]
        network_interfaces = [
            {
                "name": ni.name,
                "network": ni.network,
                "network_ip": ni.network_ip,
                "access_configs": [ac.__class__.to_dict(ac) for ac in ni.access_configs],
            }
            for ni in inst.network_interfaces
        ]

        # Firewall rules applicable to this instance
        all_rules = list(gcp.list_firewall_rules())
        instance_tags = list(inst.tags.items) if inst.tags else []
        instance_networks = [ni.network for ni in inst.network_interfaces]
        applicable = []
        for r in all_rules:
            if r.network in instance_networks and (
                not r.target_tags or any(t in instance_tags for t in r.target_tags)
            ):
                applicable.append(_serialize_firewall_rule(r))

        details = {
            "name": inst.name,
            "machine_type": inst.machine_type.split("/")[-1],
            "status": inst.status,
            "zone": inst.zone.split("/")[-1],
            "service_accounts": service_accounts,
            "network_interfaces": network_interfaces,
            "labels": dict(inst.labels) if inst.labels else None,
            "metadata": (
                {m.key: m.value for m in inst.metadata.items} if inst.metadata else None
            ),
            "applicable_firewall_rules": applicable,
        }
        result = _ok(
            f"Retrieved details for GCE instance {instance_name}",
            details,
        )
        _memory().add_gce_instance_details(project_id, instance_name, zone, result)
        return result
    except Exception as e:
        logger.exception("get_gce_instance_details failed")
        return _err(str(e))


def scan_container_image(
    project_id: str,
    resource_url: str,
    client: Optional[GcpWorkloadClient] = None,
) -> dict:
    cached = _memory().get_container_scan_result(resource_url)
    if cached:
        return {
            "status": "success",
            "message": f"(cached) {cached.get('message', '')}",
            "data": {"vulnerabilities": cached.get("vulnerabilities", [])},
        }
    try:
        raw = _client(project_id, client).get_container_vulnerabilities(resource_url)
        vulns = []
        for v in raw:
            vuln = v.vulnerability
            details = vuln.details[0] if vuln.details else None
            vulns.append(
                {
                    "cve": getattr(vuln, "cve", None) or "N/A",
                    "severity": vuln.severity.name if hasattr(vuln.severity, "name") else str(vuln.severity),
                    "description": details.description if details else "",
                }
            )
        msg = f"Found {len(vulns)} vulnerabilities in {resource_url}"
        # MemoryManager.add_container_scan_result expects pydantic objects with model_dump.
        # Wrap each dict so the existing API works without changing memory_manager.
        class _V:
            def __init__(self, d):
                self._d = d

            def model_dump(self):
                return self._d

        _memory().add_container_scan_result(resource_url, [_V(v) for v in vulns], msg)
        return _ok(msg, {"vulnerabilities": vulns})
    except Exception as e:
        logger.exception("scan_container_image failed")
        return _err(str(e))


def summarize_container_scans(
    project_id: str,
    image_urls: list[str],
    client: Optional[GcpWorkloadClient] = None,
) -> dict:
    """Aggregate severity counts per image for the unified report."""
    rows = []
    for url in image_urls:
        scan = scan_container_image(project_id, url, client=client)
        if scan.get("status") != "success":
            continue
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for v in scan["data"]["vulnerabilities"]:
            sev = (v.get("severity") or "").upper()
            if sev in counts:
                counts[sev] += 1
        rows.append({"image": url, **counts})
    return _ok(f"Summarized scans for {len(rows)} images", {"images": rows})


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

# Internet-exposed services that warrant elevated scrutiny when reachable from
# 0.0.0.0/0. Keys are TCP/UDP port strings; values are friendly service names.
_SENSITIVE_PORTS = {
    "22": "SSH",
    "23": "Telnet",
    "3389": "RDP",
    "3306": "MySQL",
    "5432": "PostgreSQL",
    "1433": "MSSQL",
    "27017": "MongoDB",
    "6379": "Redis",
}


def analyze_firewall_rules(
    project_id: str, client: Optional[GcpWorkloadClient] = None
) -> dict:
    try:
        rules_raw = list(_client(project_id, client).list_firewall_rules())
    except Exception as e:
        logger.exception("analyze_firewall_rules: list failed")
        return _err(str(e))

    issues = []
    for r in rules_raw:
        if r.disabled:
            continue
        if r.direction != "INGRESS":
            continue
        if "0.0.0.0/0" not in (r.source_ranges or []):
            continue
        for allowed in r.allowed:
            for port in (allowed.ports or []):
                if port in _SENSITIVE_PORTS:
                    issues.append(
                        {
                            "name": r.name,
                            "port": port,
                            "service": _SENSITIVE_PORTS[port],
                            "source_ranges": list(r.source_ranges),
                            "message": (
                                f"Firewall rule '{r.name}' allows unrestricted access "
                                f"to port {port} ({_SENSITIVE_PORTS[port]}) from the internet."
                            ),
                            "recommended_action": (
                                "Restrict source ranges to specific IPs/CIDRs instead of 0.0.0.0/0, "
                                "or front the workload with IAP / a bastion."
                            ),
                        }
                    )
    return _ok(
        f"Firewall analysis complete; {len(issues)} potential issue(s)",
        {"issues": issues, "total_rules": len(rules_raw)},
    )


# Roles that grant overly broad permissions at a resource level.
_OVERLY_PERMISSIVE_ROLES = {"roles/owner", "roles/editor"}
# Roles that allow service-account impersonation (privilege escalation vector).
_IMPERSONATION_ROLES = {
    "roles/iam.serviceAccountTokenCreator",
    "roles/iam.serviceAccountUser",
    "roles/iam.workloadIdentityUser",
}


def analyze_iam_privilege_escalation(
    project_id: str, client: Optional[GcpWorkloadClient] = None
) -> dict:
    try:
        policy = _client(project_id, client).get_iam_policy()
    except Exception as e:
        logger.exception("analyze_iam_privilege_escalation: get_iam_policy failed")
        return _err(str(e))

    issues = []
    for binding in policy.bindings:
        is_overly_permissive = binding.role in _OVERLY_PERMISSIVE_ROLES
        is_impersonation = binding.role in _IMPERSONATION_ROLES
        if not (is_overly_permissive or is_impersonation):
            continue
        for member in binding.members:
            if is_overly_permissive:
                issues.append(
                    {
                        "member": member,
                        "role": binding.role,
                        "message": f"'{member}' has overly permissive role '{binding.role}'.",
                        "recommended_action": (
                            "Replace with granular predefined or custom roles per the principle of least privilege."
                        ),
                    }
                )
            else:
                issues.append(
                    {
                        "member": member,
                        "role": binding.role,
                        "message": (
                            f"'{member}' can impersonate service accounts via '{binding.role}'."
                        ),
                        "recommended_action": (
                            "Limit to specific service accounts and audit usage with IAM Recommender."
                        ),
                    }
                )
    return _ok(
        f"IAM privilege-escalation analysis complete; {len(issues)} issue(s)",
        {"issues": issues},
    )
