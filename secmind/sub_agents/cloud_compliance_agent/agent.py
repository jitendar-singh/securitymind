"""
Cloud Compliance Agent - Refactored Version.

This is the main agent module that orchestrates GCP compliance checking.
It uses a modular architecture with separated concerns for better maintainability.
"""

import logging
from typing import Optional
import os

from google.adk.agents import Agent


from .models import APIResponse
from .instruction_builder import (
    build_agent_instructions,
    build_short_description,
    build_agent_name,
)
from .report_generator import generate_html_report
from .clients.base import BaseClient
from .clients.azure import AzureClient
from .clients.aws import AWSClient
from .clients.gcp import GCPClient

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ============================================================================
# TOOL FUNCTIONS
# ============================================================================
# These functions are exposed as tools to the agent. They provide a clean
# interface between the agent and the GCP client.

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
    List cloud resources using the respective cloud's Asset Inventory API.
    
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
    
    client = _get_client(cloud)
    response = client.list_resources(scope=scope, asset_types=resource_types)
    
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
    
    client = _get_client(cloud)
    response = client.list_security_sources(parent=parent)
    
    return response.to_dict()


def check_security_posture(
    cloud: str,
    parent: str,
    source_id: Optional[str] = None
) -> dict:
    """
    Check cloud security posture using the respective cloud's Security Command Center.
    
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
    
    # Default to all sources if not specified
    if source_id is None:
        source_id = "-"
    
    client = _get_client(cloud)
    response = client.list_findings(parent=parent, source_id=source_id)
    
    return response.to_dict()


def check_iam_recommendations(cloud: str, project_id: str) -> dict:
    """
    Check IAM recommendations for least privilege using the respective cloud's Recommender API.
    
    Args:
        cloud: The cloud provider to use (e.g., "gcp", "aws", "azure")
        project_id: GCP project ID (e.g., "my-project")
    
    Returns:
        Dictionary with IAM recommendations and summary
    
    Example:
        >>> check_iam_recommendations("gcp", "my-project")
    """
    logger.info(f"Tool called: check_iam_recommendations(cloud={cloud}, project_id={project_id})")
    
    client = _get_client(cloud)
    response = client.list_iam_recommendations(project_id=project_id)
    
    return response.to_dict()


def check_org_policies(cloud: str, organization_id: str) -> dict:
    """
    Check organization policies for compliance.
    
    Args:
        cloud: The cloud provider to use (e.g., "gcp", "aws", "azure")
        organization_id: GCP organization ID (numeric, e.g., "123456789")
    
    Returns:
        Dictionary with organization policies and compliance status
    
    Example:
        >>> check_org_policies("gcp", "123456789")
    """
    logger.info(f"Tool called: check_org_policies(cloud={cloud}, organization_id={organization_id})")
    
    parent = f"organizations/{organization_id}"
    client = _get_client(cloud)
    response = client.list_org_policies(parent=parent)
    
    return response.to_dict()


def check_access_keys(
    cloud: str,
    project_id: str,
    max_age_days: int = 90
) -> dict:
    """
    List and check IAM service account keys for rotation compliance.
    
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
    
    client = _get_client(cloud)
    response = client.list_service_account_keys(
        project_id=project_id,
        max_age_days=max_age_days
    )
    
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

    if org_id:
        org_policies_result = check_org_policies(cloud, org_id)
        if org_policies_result.get("status") == "success":
            all_data["org_policies"] = org_policies_result.get("data", [])

    # Generate HTML report
    try:
        html_content = generate_html_report(all_data, parent, cloud)
        report_filename = f"compliance_report_{parent.replace('/', '_')}.html"
        
        # Ensure the reports directory exists
        reports_dir = "reports"
        if not os.path.exists(reports_dir):
            os.makedirs(reports_dir)
            
        report_path = os.path.join(reports_dir, report_filename)
        
        with open(report_path, "w") as f:
            f.write(html_content)
            
        logger.info(f"Compliance report saved to {report_path}")
        return {"status": "success", "report_path": report_path}
    except Exception as e:
        logger.error(f"Failed to generate HTML report: {e}")
        return {"status": "error", "message": f"Failed to generate report: {str(e)}"}


# ============================================================================
# AGENT DEFINITION
# ============================================================================

# Define the tools available to the agent
AGENT_TOOLS = [
    list_resources,
    list_security_sources,
    check_security_posture,
    check_iam_recommendations,
    check_org_policies,
    check_access_keys,
    generate_compliance_report,
]

# Create the agent instance
cloud_compliance_agent = Agent(
    name=build_agent_name(),
    model="gemini-2.5-flash",
    description=build_short_description(),
    instruction=build_agent_instructions(),
    tools=AGENT_TOOLS,
)


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def validate_project_id(project_id: str) -> bool:
    """
    Validate project ID format.
    
    Args:
        project_id: Project ID to validate
    
    Returns:
        True if valid, False otherwise
    """
    import re
    pattern = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
    return bool(pattern.match(project_id))


def validate_organization_id(org_id: str) -> bool:
    """
    Validate organization ID format.
    
    Args:
        org_id: Organization ID to validate
    
    Returns:
        True if valid, False otherwise
    """
    import re
    pattern = re.compile(r"^[0-9]{1,19}$")
    return bool(pattern.match(org_id))


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
