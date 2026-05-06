"""GCP Workload Security sub-agent.

Thin ADK ``Agent`` wrapping the framework-free analysis functions in
``checks.py``. The same functions are imported directly by the cloud-compliance
aggregator to enrich the unified compliance report.
"""
from __future__ import annotations

import logging

from google.adk.agents import Agent

from . import checks
from .instruction_builder import (
    build_agent_instructions,
    build_agent_name,
    build_short_description,
)
from secmind.sub_agents._scope_guard import build_scope_guard

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tool functions — typed signatures for ADK; thin pass-throughs to checks.py
# ---------------------------------------------------------------------------


def list_gce_instances(project_id: str) -> dict:
    """List Compute Engine VMs in the project.

    Returns ``{"status", "message", "data": {"instances": [name, ...]}}``.
    """
    return checks.list_gce_instances(project_id)


def list_gke_clusters(project_id: str) -> dict:
    """List GKE clusters in the project (name, location, version, private flag, network)."""
    return checks.list_gke_clusters(project_id)


def list_cloud_run_services(project_id: str) -> dict:
    """List Cloud Run services in the project (name, uri, ingress, launch_stage)."""
    return checks.list_cloud_run_services(project_id)


def list_cloud_functions(project_id: str) -> dict:
    """List Cloud Functions in the project (name, runtime, environment, trigger)."""
    return checks.list_cloud_functions(project_id)


def list_firewall_rules(project_id: str) -> dict:
    """List VPC firewall rules in the project."""
    return checks.list_firewall_rules(project_id)


def get_iam_policy(project_id: str) -> dict:
    """Fetch the project-level IAM policy (bindings)."""
    return checks.get_iam_policy(project_id)


def get_gce_instance_details(project_id: str, instance_name: str, zone: str) -> dict:
    """Fetch full details for a specific GCE instance, including the firewall rules that apply to it."""
    return checks.get_gce_instance_details(project_id, instance_name, zone)


def scan_container_image(project_id: str, resource_url: str) -> dict:
    """Fetch Container Analysis vulnerability occurrences for a container image URL."""
    return checks.scan_container_image(project_id, resource_url)


def analyze_firewall_rules(project_id: str) -> dict:
    """Flag firewall rules that expose sensitive ports (SSH/RDP/MySQL/...) to 0.0.0.0/0."""
    return checks.analyze_firewall_rules(project_id)


def analyze_iam_privilege_escalation(project_id: str) -> dict:
    """Flag overly-permissive (Owner/Editor) and impersonation IAM bindings on the project."""
    return checks.analyze_iam_privilege_escalation(project_id)


AGENT_TOOLS = [
    list_gce_instances,
    list_gke_clusters,
    list_cloud_run_services,
    list_cloud_functions,
    list_firewall_rules,
    get_iam_policy,
    get_gce_instance_details,
    scan_container_image,
    analyze_firewall_rules,
    analyze_iam_privilege_escalation,
]


gcp_workload_security_agent = Agent(
    name=build_agent_name(),
    model="gemini-2.5-pro",
    description=build_short_description(),
    instruction=build_agent_instructions() + build_scope_guard(
        "GCP workload security analysis (GCE/GKE/Cloud Run/Cloud Functions, "
        "firewall analysis, IAM privilege escalation, container scans)"
    ),
    tools=AGENT_TOOLS,
    disallow_transfer_to_parent=True,
    disallow_transfer_to_peers=True,
)


__all__ = ["gcp_workload_security_agent", "AGENT_TOOLS"]
