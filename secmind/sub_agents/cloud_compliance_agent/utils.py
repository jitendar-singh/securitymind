"""
Utility functions for Cloud Compliance Agent.

This module contains helper functions for validation, formatting,
and common operations.
"""

import re
import logging
from typing import Any, Optional
from datetime import datetime, timezone

from .constants import (
    PROJECT_ID_PATTERN,
    ORG_ID_PATTERN,
    FOLDER_ID_PATTERN,
    EMAIL_PATTERN,
)

logger = logging.getLogger(__name__)


# ============================================================================
# VALIDATION FUNCTIONS
# ============================================================================

def validate_project_id(project_id: str) -> tuple[bool, Optional[str]]:
    """
    Validate GCP project ID format.
    
    Args:
        project_id: Project ID to validate
    
    Returns:
        Tuple of (is_valid, error_message)
    
    Example:
        >>> validate_project_id("my-project-123")
        (True, None)
        >>> validate_project_id("Invalid_Project")
        (False, "Invalid project ID format...")
    """
    if not project_id:
        return False, "Project ID cannot be empty"
    
    if not PROJECT_ID_PATTERN.match(project_id):
        return False, (
            f"Invalid project ID format: '{project_id}'. "
            "Must be 6-30 characters, start with lowercase letter, "
            "contain only lowercase letters, numbers, and hyphens."
        )
    
    return True, None


def validate_organization_id(org_id: str) -> tuple[bool, Optional[str]]:
    """
    Validate GCP organization ID format.
    
    Args:
        org_id: Organization ID to validate
    
    Returns:
        Tuple of (is_valid, error_message)
    
    Example:
        >>> validate_organization_id("123456789")
        (True, None)
    """
    if not org_id:
        return False, "Organization ID cannot be empty"
    
    if not ORG_ID_PATTERN.match(org_id):
        return False, (
            f"Invalid organization ID format: '{org_id}'. "
            "Must be a numeric string (1-19 digits)."
        )
    
    return True, None


def validate_folder_id(folder_id: str) -> tuple[bool, Optional[str]]:
    """
    Validate GCP folder ID format.
    
    Args:
        folder_id: Folder ID to validate
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not folder_id:
        return False, "Folder ID cannot be empty"
    
    if not FOLDER_ID_PATTERN.match(folder_id):
        return False, (
            f"Invalid folder ID format: '{folder_id}'. "
            "Must be a numeric string (1-19 digits)."
        )
    
    return True, None


def validate_email(email: str) -> tuple[bool, Optional[str]]:
    """
    Validate email address format.
    
    Args:
        email: Email address to validate
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not email:
        return False, "Email cannot be empty"
    
    if not EMAIL_PATTERN.match(email):
        return False, f"Invalid email format: '{email}'"
    
    return True, None


def validate_scope(scope: str) -> tuple[bool, Optional[str]]:
    """
    Validate GCP resource scope format.
    
    Args:
        scope: Scope string (e.g., "projects/my-project", "organizations/123")
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not scope:
        return False, "Scope cannot be empty"
    
    parts = scope.split('/')
    if len(parts) != 2:
        return False, (
            f"Invalid scope format: '{scope}'. "
            "Must be in format 'resource_type/resource_id' "
            "(e.g., 'projects/my-project', 'organizations/123')"
        )
    
    resource_type, resource_id = parts
    
    if resource_type == "projects":
        return validate_project_id(resource_id)
    elif resource_type == "organizations":
        return validate_organization_id(resource_id)
    elif resource_type == "folders":
        return validate_folder_id(resource_id)
    else:
        return False, (
            f"Unknown resource type: '{resource_type}'. "
            "Must be one of: projects, organizations, folders"
        )


# ============================================================================
# FORMATTING FUNCTIONS
# ============================================================================

def format_severity(severity: str) -> str:
    """
    Format severity level with emoji indicator.
    
    Args:
        severity: Severity level string
    
    Returns:
        Formatted severity string with emoji
    """
    severity_map = {
        "CRITICAL": "🔴 CRITICAL",
        "HIGH": "🟠 HIGH",
        "MEDIUM": "🟡 MEDIUM",
        "LOW": "🟢 LOW",
        "INFO": "🔵 INFO",
    }
    return severity_map.get(severity.upper(), severity)


def format_timestamp(dt: datetime) -> str:
    """
    Format datetime to human-readable string.
    
    Args:
        dt: Datetime object
    
    Returns:
        Formatted timestamp string
    """
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def format_age_days(days: int) -> str:
    """
    Format age in days to human-readable string.
    
    Args:
        days: Number of days
    
    Returns:
        Formatted age string
    """
    if days == 0:
        return "Today"
    elif days == 1:
        return "1 day ago"
    elif days < 30:
        return f"{days} days ago"
    elif days < 365:
        months = days // 30
        return f"{months} month{'s' if months > 1 else ''} ago"
    else:
        years = days // 365
        return f"{years} year{'s' if years > 1 else ''} ago"


def format_percentage(value: float, decimals: int = 1) -> str:
    """
    Format percentage value.
    
    Args:
        value: Percentage value (0-100)
        decimals: Number of decimal places
    
    Returns:
        Formatted percentage string
    """
    return f"{value:.{decimals}f}%"


def format_risk_score(score: int) -> str:
    """
    Format risk score with severity indicator.
    
    Args:
        score: Risk score value
    
    Returns:
        Formatted risk score string
    """
    if score >= 50:
        return f"🔴 {score} (Critical)"
    elif score >= 30:
        return f"🟠 {score} (High)"
    elif score >= 15:
        return f"🟡 {score} (Medium)"
    else:
        return f"🟢 {score} (Low)"


# ============================================================================
# DATA TRANSFORMATION FUNCTIONS
# ============================================================================

def truncate_string(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """
    Truncate string to maximum length.
    
    Args:
        text: String to truncate
        max_length: Maximum length
        suffix: Suffix to append if truncated
    
    Returns:
        Truncated string
    """
    if len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix


def sanitize_resource_name(name: str) -> str:
    """
    Sanitize resource name for display.
    
    Args:
        name: Resource name
    
    Returns:
        Sanitized name
    """
    # Extract the last part of the resource name (after last /)
    if '/' in name:
        return name.split('/')[-1]
    return name


def group_by_severity(findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """
    Group findings by severity level.
    
    Args:
        findings: List of finding dictionaries
    
    Returns:
        Dictionary mapping severity to list of findings
    """
    grouped = {
        "CRITICAL": [],
        "HIGH": [],
        "MEDIUM": [],
        "LOW": [],
        "INFO": [],
    }
    
    for finding in findings:
        severity = finding.get("severity", "INFO").upper()
        if severity in grouped:
            grouped[severity].append(finding)
        else:
            grouped["INFO"].append(finding)
    
    return grouped


def calculate_age_days(create_time: datetime) -> int:
    """
    Calculate age in days from creation time.
    
    Args:
        create_time: Creation timestamp
    
    Returns:
        Age in days
    """
    now = datetime.now(timezone.utc)
    if create_time.tzinfo is None:
        create_time = create_time.replace(tzinfo=timezone.utc)
    
    delta = now - create_time
    return delta.days


# ============================================================================
# FILTERING FUNCTIONS
# ============================================================================

def filter_active_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Filter to only active findings.
    
    Args:
        findings: List of finding dictionaries
    
    Returns:
        List of active findings
    """
    return [f for f in findings if f.get("state", "").upper() == "ACTIVE"]


def filter_by_severity(
    findings: list[dict[str, Any]],
    min_severity: str = "LOW"
) -> list[dict[str, Any]]:
    """
    Filter findings by minimum severity level.
    
    Args:
        findings: List of finding dictionaries
        min_severity: Minimum severity level (CRITICAL, HIGH, MEDIUM, LOW)
    
    Returns:
        Filtered list of findings
    """
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    
    try:
        min_index = severity_order.index(min_severity.upper())
    except ValueError:
        logger.warning(f"Invalid severity level: {min_severity}, using LOW")
        min_index = severity_order.index("LOW")
    
    return [
        f for f in findings
        if severity_order.index(f.get("severity", "INFO").upper()) <= min_index
    ]


def filter_non_compliant_keys(
    keys: list[dict[str, Any]],
    max_age_days: int = 90
) -> list[dict[str, Any]]:
    """
    Filter to only non-compliant keys.
    
    Args:
        keys: List of key dictionaries
        max_age_days: Maximum age for compliance
    
    Returns:
        List of non-compliant keys
    """
    return [k for k in keys if k.get("age_days", 0) > max_age_days]


# ============================================================================
# SUMMARY FUNCTIONS
# ============================================================================

def generate_findings_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Generate summary statistics for findings.
    
    Args:
        findings: List of finding dictionaries
    
    Returns:
        Summary dictionary
    """
    grouped = group_by_severity(findings)
    active = filter_active_findings(findings)
    
    return {
        "total_findings": len(findings),
        "critical_count": len(grouped["CRITICAL"]),
        "high_count": len(grouped["HIGH"]),
        "medium_count": len(grouped["MEDIUM"]),
        "low_count": len(grouped["LOW"]),
        "info_count": len(grouped["INFO"]),
        "active_count": len(active),
        "inactive_count": len(findings) - len(active),
        "risk_score": (
            len(grouped["CRITICAL"]) * 10 +
            len(grouped["HIGH"]) * 7 +
            len(grouped["MEDIUM"]) * 4 +
            len(grouped["LOW"]) * 2
        ),
    }


def generate_compliance_summary(
    total_checks: int,
    compliant_checks: int
) -> dict[str, Any]:
    """
    Generate compliance summary.
    
    Args:
        total_checks: Total number of checks performed
        compliant_checks: Number of compliant checks
    
    Returns:
        Compliance summary dictionary
    """
    if total_checks == 0:
        percentage = 0.0
    else:
        percentage = (compliant_checks / total_checks) * 100
    
    return {
        "total_checks": total_checks,
        "compliant_checks": compliant_checks,
        "non_compliant_checks": total_checks - compliant_checks,
        "compliance_percentage": percentage,
        "status": "COMPLIANT" if percentage >= 80 else "NON_COMPLIANT",
    }


# ============================================================================
# LOGGING HELPERS
# ============================================================================

def log_api_call(
    function_name: str,
    params: dict[str, Any],
    success: bool = True,
    error: Optional[str] = None
) -> None:
    """
    Log API call for debugging and monitoring.
    
    Args:
        function_name: Name of the function called
        params: Parameters passed to the function
        success: Whether the call was successful
        error: Error message if failed
    """
    if success:
        logger.info(f"API call succeeded: {function_name}({params})")
    else:
        logger.error(f"API call failed: {function_name}({params}) - Error: {error}")


def log_validation_error(field: str, value: Any, error: str) -> None:
    """
    Log validation error.
    
    Args:
        field: Field name that failed validation
        value: Value that failed validation
        error: Error message
    """
    logger.warning(f"Validation failed for {field}='{value}': {error}")
