"""
Cloud Compliance Agent - Refactored Version.

This is the main agent module that orchestrates GCP compliance checking.
It uses a modular architecture with separated concerns for better maintainability.
"""

import logging
import re
from datetime import datetime
from typing import Optional
import os

from google.adk.agents import Agent


from .models import APIResponse, ComplianceAssessment
from .instruction_builder import (
    build_agent_instructions,
    build_short_description,
    build_agent_name,
)
from secmind.sub_agents._scope_guard import build_scope_guard
from .report_generator import generate_html_report
from .clients.base import BaseClient
from .clients.azure import AzureClient
from .clients.aws import AWSClient
from .clients.gcp import GCPClient
from secmind.memory import get_memory_manager

logger = logging.getLogger(__name__)


# ============================================================================
# TOOL FUNCTIONS
# ============================================================================
# These functions are exposed as tools to the agent. They provide a clean
# interface between the agent and the GCP client.

SUPPORTED_CLOUDS = {"gcp", "aws", "azure"}
_PROJECT_ID_RE = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
_ORG_ID_RE = re.compile(r"^[0-9]{1,19}$")


def validate_project_id(project_id: str) -> bool:
    return bool(_PROJECT_ID_RE.match(project_id))


def validate_organization_id(org_id: str) -> bool:
    return bool(_ORG_ID_RE.match(org_id))


def _validate_cloud(cloud: str) -> Optional[dict]:
    if cloud not in SUPPORTED_CLOUDS:
        return {"status": "error", "message": f"Unsupported cloud provider '{cloud}'. Must be one of: {sorted(SUPPORTED_CLOUDS)}"}
    return None


def _validate_scope(scope: str) -> Optional[dict]:
    if scope.startswith("projects/"):
        project_id = scope.split("/", 1)[1]
        if not validate_project_id(project_id):
            return {"status": "error", "message": f"Invalid project ID in scope: '{project_id}'"}
    elif scope.startswith("organizations/"):
        org_id = scope.split("/", 1)[1]
        if not validate_organization_id(org_id):
            return {"status": "error", "message": f"Invalid organization ID in scope: '{org_id}'"}
    else:
        return {"status": "error", "message": f"Invalid scope '{scope}'. Must start with 'projects/' or 'organizations/'"}
    return None


# Global client instances (initialized lazily)
_clients: dict[str, BaseClient] = {}


def _get_client(cloud: str) -> BaseClient:
    """Get or create the global GCP client instance."""
    global _clients
    if cloud not in _clients:
        if cloud == "gcp":
            _clients[cloud] = GCPClient()
            logger.info("Initialized GCP client")
        elif cloud == "aws":
            _clients[cloud] = AWSClient()
            logger.info("Initialized AWS client")
        elif cloud == "azure":
            _clients[cloud] = AzureClient()
            logger.info("Initialized Azure client")
        else:
            raise ValueError(f"Unsupported cloud provider: {cloud}")
    return _clients[cloud]


def list_resources(
    cloud: str,
    scope: str,
    resource_types: Optional[list[str]] = None
) -> dict:
    """
    List cloud resources using the respective cloud's Asset Inventory API, with caching.
    
    Args:
        cloud: The cloud provider to use (e.g., "gcp", "aws", "azure")
        scope: Scope to search (e.g., "projects/my-project", "organizations/123")
        resource_types: List of specific resource types to filter (None for all)
    
    Returns:
        Dictionary with status, data, and message
    
    Example:
        >>> list_resources("gcp", "projects/my-project")
        >>> list_resources("gcp", "projects/my-project", ["compute.googleapis.com/Instance"])
    """
    logger.info(f"Tool called: list_resources(cloud={cloud}, scope={scope}, resource_types={resource_types})")

    if (err := _validate_cloud(cloud)):
        return err
    if (err := _validate_scope(scope)):
        return err

    memory = get_memory_manager()
    
    # Check cache first
    cached_resources = memory.get_cloud_resources(scope, resource_types)
    if cached_resources:
        return cached_resources

    client = _get_client(cloud)
    response = client.list_resources(scope=scope, asset_types=resource_types)
    
    # Add to cache
    if response.status == "success":
        memory.add_cloud_resources(scope, resource_types, response.to_dict())
    
    return response.to_dict()


def list_security_sources(cloud: str, parent: str) -> dict:
    """
    List security sources in the respective cloud's Security Command Center.
    
    Args:
        cloud: The cloud provider to use (e.g., "gcp", "aws", "azure")
        parent: Parent resource (e.g., "organizations/123", "projects/my-project")
    
    Returns:
        Dictionary with status, data, and message
    
    Example:
        >>> list_security_sources("gcp", "organizations/123456789")
        >>> list_security_sources("gcp", "projects/my-project")
    """
    logger.info(f"Tool called: list_security_sources(cloud={cloud}, parent={parent})")

    if (err := _validate_cloud(cloud)):
        return err
    if (err := _validate_scope(parent)):
        return err

    client = _get_client(cloud)
    response = client.list_security_sources(parent=parent)
    
    return response.to_dict()


def check_security_posture(
    cloud: str,
    parent: str,
    source_id: Optional[str] = None
) -> dict:
    """
    Check cloud security posture using the respective cloud's Security Command Center, with caching.
    
    Args:
        cloud: The cloud provider to use (e.g., "gcp", "aws", "azure")
        parent: Parent resource (e.g., "organizations/123", "projects/my-project")
        source_id: Specific source ID to filter (use "-" for all sources, None defaults to all)
    
    Returns:
        Dictionary with findings and summary statistics
    
    Example:
        >>> check_security_posture("gcp", "projects/my-project")
        >>> check_security_posture("gcp", "organizations/123", source_id="specific-source-id")
    """
    logger.info(f"Tool called: check_security_posture(cloud={cloud}, parent={parent}, source_id={source_id})")

    if (err := _validate_cloud(cloud)):
        return err
    if (err := _validate_scope(parent)):
        return err

    memory = get_memory_manager()

    # Check cache first
    cached_posture = memory.get_security_posture(parent, source_id)
    if cached_posture:
        return cached_posture

    # Default to all sources if not specified
    if source_id is None:
        source_id = "-"
    
    client = _get_client(cloud)
    response = client.list_findings(parent=parent, source_id=source_id)
    
    # Add to cache
    if response.status == "success":
        memory.add_security_posture(parent, source_id, response.to_dict())
    
    return response.to_dict()


def check_iam_recommendations(cloud: str, project_id: str) -> dict:
    """
    Check IAM recommendations for least privilege using the respective cloud's Recommender API, with caching.
    
    Args:
        cloud: The cloud provider to use (e.g., "gcp", "aws", "azure")
        project_id: GCP project ID (e.g., "my-project")
    
    Returns:
        Dictionary with IAM recommendations and summary
    
    Example:
        >>> check_iam_recommendations("gcp", "my-project")
    """
    logger.info(f"Tool called: check_iam_recommendations(cloud={cloud}, project_id={project_id})")

    if (err := _validate_cloud(cloud)):
        return err
    if not validate_project_id(project_id):
        return {"status": "error", "message": f"Invalid project ID: '{project_id}'"}

    memory = get_memory_manager()

    # Check cache first
    cached_recommendations = memory.get_iam_recommendations(project_id)
    if cached_recommendations:
        return cached_recommendations

    client = _get_client(cloud)
    response = client.list_iam_recommendations(project_id=project_id)
    
    # Add to cache
    if response.status == "success":
        memory.add_iam_recommendations(project_id, response.to_dict())
    
    return response.to_dict()


def check_org_policies(cloud: str, organization_id: str) -> dict:
    """
    Check organization policies for compliance, with caching.
    
    Args:
        cloud: The cloud provider to use (e.g., "gcp", "aws", "azure")
        organization_id: GCP organization ID (numeric, e.g., "123456789")
    
    Returns:
        Dictionary with organization policies and compliance status
    
    Example:
        >>> check_org_policies("gcp", "123456789")
    """
    logger.info(f"Tool called: check_org_policies(cloud={cloud}, organization_id={organization_id})")

    if (err := _validate_cloud(cloud)):
        return err
    if not validate_organization_id(organization_id):
        return {"status": "error", "message": f"Invalid organization ID: '{organization_id}'. Must be numeric (1–19 digits)"}

    memory = get_memory_manager()

    # Check cache first
    cached_policies = memory.get_org_policies(organization_id)
    if cached_policies:
        return cached_policies

    parent = f"organizations/{organization_id}"
    client = _get_client(cloud)
    response = client.list_org_policies(parent=parent)
    
    # Add to cache
    if response.status == "success":
        memory.add_org_policies(organization_id, response.to_dict())
    
    return response.to_dict()


def check_access_keys(
    cloud: str,
    project_id: str,
    max_age_days: int = 90
) -> dict:
    """
    List and check IAM service account keys for rotation compliance, with caching.
    
    Args:
        cloud: The cloud provider to use (e.g., "gcp", "aws", "azure")
        project_id: GCP project ID (e.g., "my-project")
        max_age_days: Maximum age in days for compliance (default: 90)
    
    Returns:
        Dictionary with keys, non-compliant keys, and summary
    
    Example:
        >>> check_access_keys("gcp", "my-project")
        >>> check_access_keys("gcp", "my-project", max_age_days=30)
    """
    logger.info(f"Tool called: check_access_keys(cloud={cloud}, project_id={project_id}, max_age_days={max_age_days})")

    if (err := _validate_cloud(cloud)):
        return err
    if not validate_project_id(project_id):
        return {"status": "error", "message": f"Invalid project ID: '{project_id}'"}
    if not isinstance(max_age_days, int) or max_age_days <= 0:
        return {"status": "error", "message": f"max_age_days must be a positive integer, got: {max_age_days!r}"}

    memory = get_memory_manager()

    # Check cache first
    cached_keys = memory.get_access_keys(project_id, max_age_days)
    if cached_keys:
        return cached_keys

    client = _get_client(cloud)
    response = client.list_service_account_keys(
        project_id=project_id,
        max_age_days=max_age_days
    )
    
    # Add to cache
    if response.status == "success":
        memory.add_access_keys(project_id, max_age_days, response.to_dict())
    
    return response.to_dict()


def check_public_gcs_buckets(cloud: str, project_id: str) -> dict:
    """
    Check for publicly accessible GCS buckets, with caching.

    Args:
        cloud: The cloud provider to use (e.g., "gcp")
        project_id: GCP project ID (e.g., "my-project")

    Returns:
        Dictionary with a list of public buckets and a summary.

    Example:
        >>> check_public_gcs_buckets("gcp", "my-project")
    """
    logger.info(f"Tool called: check_public_gcs_buckets(cloud={cloud}, project_id={project_id})")

    if (err := _validate_cloud(cloud)):
        return err
    if not validate_project_id(project_id):
        return {"status": "error", "message": f"Invalid project ID: '{project_id}'"}

    memory = get_memory_manager()

    # Check cache first
    cached_buckets = memory.get_public_gcs_buckets(project_id)
    if cached_buckets:
        return cached_buckets

    client = _get_client(cloud)
    response = client.list_public_gcs_buckets(project_id=project_id)

    # Add to cache
    if response.status == "success":
        memory.add_public_gcs_buckets(project_id, response.to_dict())

    return response.to_dict()


# ============================================================================
# NETWORK & DATA-SECURITY TOOLS (M2)
# ============================================================================


def check_vpc_flow_logs(cloud: str, project_id: str) -> dict:
    """Report which subnets in the project have VPC flow logs disabled.

    Args:
        cloud: Cloud provider (only "gcp" is supported here).
        project_id: GCP project ID.
    """
    logger.info(f"Tool called: check_vpc_flow_logs(cloud={cloud}, project_id={project_id})")
    if (err := _validate_cloud(cloud)):
        return err
    if not validate_project_id(project_id):
        return {"status": "error", "message": f"Invalid project ID: '{project_id}'"}

    memory = get_memory_manager()
    cached = memory.get_vpc_flow_logs(project_id)
    if cached:
        return {"status": "success", "data": cached, "message": "(cached)"}

    response = _get_client(cloud).list_subnetworks_flow_log_status(project_id=project_id)
    if response.status == "success":
        memory.add_vpc_flow_logs(project_id, response.data)
    return response.to_dict()


def check_default_network(cloud: str, project_id: str) -> dict:
    """Detect whether the project still has the GCP default VPC network."""
    logger.info(f"Tool called: check_default_network(cloud={cloud}, project_id={project_id})")
    if (err := _validate_cloud(cloud)):
        return err
    if not validate_project_id(project_id):
        return {"status": "error", "message": f"Invalid project ID: '{project_id}'"}

    memory = get_memory_manager()
    cached = memory.get_default_network(project_id)
    if cached:
        return {"status": "success", "data": cached, "message": "(cached)"}

    response = _get_client(cloud).get_default_network(project_id=project_id)
    if response.status == "success":
        memory.add_default_network(project_id, response.data)
    return response.to_dict()


def check_kms_key_rotation(cloud: str, project_id: str, max_rotation_days: int = 90) -> dict:
    """Find Cloud KMS keys that have no rotation period set or rotate slower than max_rotation_days."""
    logger.info(
        f"Tool called: check_kms_key_rotation(cloud={cloud}, project_id={project_id}, "
        f"max_rotation_days={max_rotation_days})"
    )
    if (err := _validate_cloud(cloud)):
        return err
    if not validate_project_id(project_id):
        return {"status": "error", "message": f"Invalid project ID: '{project_id}'"}

    memory = get_memory_manager()
    cached = memory.get_kms_rotation(project_id, max_rotation_days)
    if cached:
        return {"status": "success", "data": cached, "message": "(cached)"}

    response = _get_client(cloud).list_kms_key_rotation_issues(
        project_id=project_id, max_rotation_days=max_rotation_days
    )
    if response.status == "success":
        memory.add_kms_rotation(project_id, max_rotation_days, response.data)
    return response.to_dict()


def check_secrets(cloud: str, project_id: str, max_age_days: int = 90) -> dict:
    """List Secret Manager secrets, flagging stale ones (>max_age_days) and any with public bindings."""
    logger.info(
        f"Tool called: check_secrets(cloud={cloud}, project_id={project_id}, max_age_days={max_age_days})"
    )
    if (err := _validate_cloud(cloud)):
        return err
    if not validate_project_id(project_id):
        return {"status": "error", "message": f"Invalid project ID: '{project_id}'"}

    memory = get_memory_manager()
    cached = memory.get_secrets(project_id, max_age_days)
    if cached:
        return {"status": "success", "data": cached, "message": "(cached)"}

    response = _get_client(cloud).list_secret_manager_secrets(
        project_id=project_id, max_age_days=max_age_days
    )
    if response.status == "success":
        memory.add_secrets(project_id, max_age_days, response.data)
    return response.to_dict()


def check_public_bigquery_datasets(cloud: str, project_id: str) -> dict:
    """Find BigQuery datasets exposed to allUsers or allAuthenticatedUsers."""
    logger.info(
        f"Tool called: check_public_bigquery_datasets(cloud={cloud}, project_id={project_id})"
    )
    if (err := _validate_cloud(cloud)):
        return err
    if not validate_project_id(project_id):
        return {"status": "error", "message": f"Invalid project ID: '{project_id}'"}

    memory = get_memory_manager()
    cached = memory.get_public_bq_datasets(project_id)
    if cached:
        return {"status": "success", "data": cached, "message": "(cached)"}

    response = _get_client(cloud).list_public_bigquery_datasets(project_id=project_id)
    if response.status == "success":
        memory.add_public_bq_datasets(project_id, response.data)
    return response.to_dict()


def check_dnssec(cloud: str, project_id: str) -> dict:
    """Report Cloud DNS managed zones with DNSSEC disabled."""
    logger.info(f"Tool called: check_dnssec(cloud={cloud}, project_id={project_id})")
    if (err := _validate_cloud(cloud)):
        return err
    if not validate_project_id(project_id):
        return {"status": "error", "message": f"Invalid project ID: '{project_id}'"}

    memory = get_memory_manager()
    cached = memory.get_dnssec(project_id)
    if cached:
        return {"status": "success", "data": cached, "message": "(cached)"}

    response = _get_client(cloud).list_dnssec_status(project_id=project_id)
    if response.status == "success":
        memory.add_dnssec(project_id, response.data)
    return response.to_dict()


def check_cloud_armor(cloud: str, project_id: str) -> dict:
    """Enumerate Cloud Armor policies and flag internet-facing backends without one."""
    logger.info(f"Tool called: check_cloud_armor(cloud={cloud}, project_id={project_id})")
    if (err := _validate_cloud(cloud)):
        return err
    if not validate_project_id(project_id):
        return {"status": "error", "message": f"Invalid project ID: '{project_id}'"}

    memory = get_memory_manager()
    cached = memory.get_cloud_armor(project_id)
    if cached:
        return {"status": "success", "data": cached, "message": "(cached)"}

    response = _get_client(cloud).list_cloud_armor_coverage(project_id=project_id)
    if response.status == "success":
        memory.add_cloud_armor(project_id, response.data)
    return response.to_dict()


def generate_compliance_report(cloud: str, parent: str) -> dict:
    """
    Generates a comprehensive compliance report in HTML format.

    Args:
        cloud: The cloud provider to use (e.g., "gcp", "aws", "azure")
        parent: The cloud parent (e.g., "projects/my-project" or "organizations/12345").

    Returns:
        A dictionary with the status and path to the generated report.
    """
    logger.info(f"Generating compliance report for {parent}")

    if (err := _validate_cloud(cloud)):
        return err
    if (err := _validate_scope(parent)):
        return err

    all_data = {}

    # Determine if parent is a project or organization
    is_project = parent.startswith("projects/")
    is_org = parent.startswith("organizations/")
    project_id = parent.split("/")[1] if is_project else None
    org_id = parent.split("/")[1] if is_org else None

    # Gather data from other tools
    posture_result = check_security_posture(cloud, parent)
    if posture_result.get("status") == "success":
        all_data["posture"] = posture_result.get("data", {})

    if project_id:
        iam_result = check_iam_recommendations(cloud, project_id)
        if iam_result.get("status") == "success":
            all_data["iam_recommendations"] = iam_result.get("data", [])
        
        keys_result = check_access_keys(cloud, project_id)
        if keys_result.get("status") == "success":
            all_data["access_keys"] = keys_result.get("data", {})

        buckets_result = check_public_gcs_buckets(cloud, project_id)
        if buckets_result.get("status") == "success":
            all_data["public_gcs_buckets"] = buckets_result.get("data", {})

    if org_id:
        org_policies_result = check_org_policies(cloud, org_id)
        if org_policies_result.get("status") == "success":
            all_data["org_policies"] = org_policies_result.get("data", [])

    # Workload security analyses are owned by gcp_workload_security_agent but
    # exposed as plain functions in checks.py for programmatic aggregation here.
    if project_id and cloud == "gcp":
        from secmind.sub_agents.gcp_workload_security_agent import checks as workload_checks
        fw_analysis = workload_checks.analyze_firewall_rules(project_id)
        if fw_analysis.get("status") == "success":
            all_data["risky_firewall_rules"] = fw_analysis.get("data", {})
        iam_priv = workload_checks.analyze_iam_privilege_escalation(project_id)
        if iam_priv.get("status") == "success":
            all_data["privileged_iam_bindings"] = iam_priv.get("data", {})

        # Network & data-security checks
        for key, fn in [
            ("vpc_flow_logs", check_vpc_flow_logs),
            ("default_network", check_default_network),
            ("kms_rotation", check_kms_key_rotation),
            ("secrets", check_secrets),
            ("public_bigquery_datasets", check_public_bigquery_datasets),
            ("dnssec_status", check_dnssec),
            ("cloud_armor_coverage", check_cloud_armor),
        ]:
            res = fn(cloud, project_id)
            if res.get("status") == "success":
                all_data[key] = res.get("data", {})

    # Generate HTML report
    try:
        html_content = generate_html_report(all_data, parent, cloud)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        report_filename = f"compliance_report_{parent.replace('/', '_')}-{ts}.html"
        from secmind.reports import user_reports_dir
        reports_dir = user_reports_dir()
        report_path = os.path.join(reports_dir, report_filename)
        
        with open(report_path, "w") as f:
            f.write(html_content)

        logger.info(f"Compliance report saved to {report_path}")
        # Intentionally do NOT return the report_path — the user-facing message
        # should not include the filesystem path. The Reports page lists all
        # generated reports for the user.
        return {"status": "success", "message": "The compliance report has been successfully generated."}
    except Exception as e:
        logger.error(f"Failed to generate HTML report: {e}")
        return {"status": "error", "message": f"Failed to generate report: {str(e)}"}


# ============================================================================
# AGENT DEFINITION
# ============================================================================

# Define the tools available to the agent. Workload-security tools live on the
# peer gcp_workload_security_agent — the master agent routes those queries
# directly. The shared analysis functions are imported from that module's
# checks.py inside generate_compliance_report below.
AGENT_TOOLS = [
    list_resources,
    list_security_sources,
    check_security_posture,
    check_iam_recommendations,
    check_org_policies,
    check_access_keys,
    check_public_gcs_buckets,
    check_vpc_flow_logs,
    check_default_network,
    check_kms_key_rotation,
    check_secrets,
    check_public_bigquery_datasets,
    check_dnssec,
    check_cloud_armor,
    generate_compliance_report,
]

# Create the agent instance
cloud_compliance_agent = Agent(
    name=build_agent_name(),
    model="gemini-2.5-pro",
    description=build_short_description(),
    instruction=build_agent_instructions() + build_scope_guard(
        "cloud security compliance assessments for GCP, AWS, and Azure"
    ),
    tools=AGENT_TOOLS,
    output_schema=ComplianceAssessment,
    disallow_transfer_to_parent=True,
    disallow_transfer_to_peers=True,
)


# ============================================================================
# MAIN EXECUTION
# ============================================================================

if __name__ == "__main__":
    """
    Example usage and testing.
    """
    logger.info("Cloud Compliance Agent initialized")
    logger.info(f"Agent name: {cloud_compliance_agent.name}")
    logger.info(f"Available tools: {[tool.__name__ for tool in AGENT_TOOLS]}")

    # Example: Test project ID validation
    test_project_ids = [
        "my-project-123",  # Valid
        "MyProject",       # Invalid (uppercase)
        "a",               # Invalid (too short)
        "my_project",      # Invalid (underscore)
    ]

    print("\nProject ID Validation Tests:")
    for pid in test_project_ids:
        is_valid = validate_project_id(pid)
        print(f"  {pid}: {'✓ Valid' if is_valid else '✗ Invalid'}")

    # Example: Test organization ID validation
    test_org_ids = [
        "123456789",       # Valid
        "abc123",          # Invalid (contains letters)
        "12345678901234567890",  # Invalid (too long)
    ]

    print("\nOrganization ID Validation Tests:")
    for oid in test_org_ids:
        is_valid = validate_organization_id(oid)
        print(f"  {oid}: {'✓ Valid' if is_valid else '✗ Invalid'}")

    # Example: Test multi-cloud client initialization
    print("\nMulti-cloud Client Initialization Tests:")
    try:
        _get_client("gcp")
        print("  ✓ GCP client initialized successfully")
    except Exception as e:
        print(f"  ✗ GCP client initialization failed: {e}")

    try:
        _get_client("aws")
        print("  ✓ AWS client initialized successfully")
    except Exception as e:
        print(f"  ✗ AWS client initialization failed: {e}")

    try:
        _get_client("azure")
        print("  ✓ Azure client initialized successfully")
    except Exception as e:
        print(f"  ✗ Azure client initialization failed: {e}")

    try:
        _get_client("invalid_cloud")
        print("  ✗ Invalid cloud client should have failed but was initialized")
    except ValueError as e:
        print(f"  ✓ Correctly failed to initialize invalid cloud client: {e}")
    except Exception as e:
        print(f"  ✗ Incorrect exception type for invalid cloud client: {e}")

    print("\n✅ Cloud Compliance Agent ready!")
