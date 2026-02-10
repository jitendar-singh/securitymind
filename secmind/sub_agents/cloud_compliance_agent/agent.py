"""
Cloud Compliance Agent - Refactored Version.

This is the main agent module that orchestrates GCP compliance checking.
It uses a modular architecture with separated concerns for better maintainability.
"""

import logging
from typing import Optional

from google.adk.agents import Agent
from .gcp_client import GCPClient

from .models import APIResponse
from .instruction_builder import (
    build_agent_instructions,
    build_short_description,
    build_agent_name,
)

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

# Global GCP client instance (initialized lazily)
_gcp_client: Optional[GCPClient] = None


def _get_gcp_client() -> GCPClient:
    """Get or create the global GCP client instance."""
    global _gcp_client
    if _gcp_client is None:
        _gcp_client = GCPClient()
        logger.info("Initialized GCP client")
    return _gcp_client


def list_gcp_resources(
    scope: str,
    resource_types: Optional[list[str]] = None
) -> dict:
    """
    List GCP resources using Asset Inventory API.
    
    Args:
        scope: Scope to search (e.g., "projects/my-project", "organizations/123")
        resource_types: List of specific resource types to filter (None for all)
    
    Returns:
        Dictionary with status, data, and message
    
    Example:
        >>> list_gcp_resources("projects/my-project")
        >>> list_gcp_resources("projects/my-project", ["compute.googleapis.com/Instance"])
    """
    logger.info(f"Tool called: list_gcp_resources(scope={scope}, resource_types={resource_types})")
    
    client = _get_gcp_client()
    response = client.list_resources(scope=scope, asset_types=resource_types)
    
    return response.to_dict()


def list_security_sources(parent: str) -> dict:
    """
    List security sources in Security Command Center.
    
    Args:
        parent: Parent resource (e.g., "organizations/123", "projects/my-project")
    
    Returns:
        Dictionary with status, data, and message
    
    Example:
        >>> list_security_sources("organizations/123456789")
        >>> list_security_sources("projects/my-project")
    """
    logger.info(f"Tool called: list_security_sources(parent={parent})")
    
    client = _get_gcp_client()
    response = client.list_security_sources(parent=parent)
    
    return response.to_dict()


def check_security_posture(
    parent: str,
    source_id: Optional[str] = None
) -> dict:
    """
    Check cloud security posture using Security Command Center.
    
    Args:
        parent: Parent resource (e.g., "organizations/123", "projects/my-project")
        source_id: Specific source ID to filter (use "-" for all sources, None defaults to all)
    
    Returns:
        Dictionary with findings and summary statistics
    
    Example:
        >>> check_security_posture("projects/my-project")
        >>> check_security_posture("organizations/123", source_id="specific-source-id")
    """
    logger.info(f"Tool called: check_security_posture(parent={parent}, source_id={source_id})")
    
    # Default to all sources if not specified
    if source_id is None:
        source_id = "-"
    
    client = _get_gcp_client()
    response = client.list_findings(parent=parent, source_id=source_id)
    
    return response.to_dict()


def check_iam_recommendations(project_id: str) -> dict:
    """
    Check IAM recommendations for least privilege using Recommender API.
    
    Args:
        project_id: GCP project ID (e.g., "my-project")
    
    Returns:
        Dictionary with IAM recommendations and summary
    
    Example:
        >>> check_iam_recommendations("my-project")
    """
    logger.info(f"Tool called: check_iam_recommendations(project_id={project_id})")
    
    client = _get_gcp_client()
    response = client.list_iam_recommendations(project_id=project_id)
    
    return response.to_dict()


def check_org_policies(organization_id: str) -> dict:
    """
    Check organization policies for compliance.
    
    Args:
        organization_id: GCP organization ID (numeric, e.g., "123456789")
    
    Returns:
        Dictionary with organization policies and compliance status
    
    Example:
        >>> check_org_policies("123456789")
    """
    logger.info(f"Tool called: check_org_policies(organization_id={organization_id})")
    
    parent = f"organizations/{organization_id}"
    client = _get_gcp_client()
    response = client.list_org_policies(parent=parent)
    
    return response.to_dict()


def check_access_keys(
    project_id: str,
    max_age_days: int = 90
) -> dict:
    """
    List and check IAM service account keys for rotation compliance.
    
    Args:
        project_id: GCP project ID (e.g., "my-project")
        max_age_days: Maximum age in days for compliance (default: 90)
    
    Returns:
        Dictionary with keys, non-compliant keys, and summary
    
    Example:
        >>> check_access_keys("my-project")
        >>> check_access_keys("my-project", max_age_days=30)
    """
    logger.info(f"Tool called: check_access_keys(project_id={project_id}, max_age_days={max_age_days})")
    
    client = _get_gcp_client()
    response = client.list_service_account_keys(
        project_id=project_id,
        max_age_days=max_age_days
    )
    
    return response.to_dict()


# ============================================================================
# AGENT DEFINITION
# ============================================================================

# Define the tools available to the agent
AGENT_TOOLS = [
    list_gcp_resources,
    list_security_sources,
    check_security_posture,
    check_iam_recommendations,
    check_org_policies,
    check_access_keys,
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
    Validate GCP project ID format.
    
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
    Validate GCP organization ID format.
    
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
    
    print("\n✅ Cloud Compliance Agent ready!")
