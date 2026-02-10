"""
Utility functions for vulnerability triage agent.
"""

import re
import logging
from typing import Optional
from functools import lru_cache

logger = logging.getLogger(__name__)


def extract_cve_id(text: str) -> Optional[str]:
    """
    Extract CVE ID from text.
    
    Args:
        text: Text containing potential CVE ID
        
    Returns:
        CVE ID in uppercase, or None if not found
        
    Example:
        >>> extract_cve_id("Found CVE-2023-1234 in package")
        'CVE-2023-1234'
    """
    if not text:
        return None
        
    match = re.search(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE)
    if match:
        cve_id = match.group(0).upper()
        logger.debug(f"Extracted CVE ID: {cve_id}")
        return cve_id
    
    logger.warning(f"No CVE ID found in text: {text[:100]}")
    return None


def is_copyleft_license(license_text: str, copyleft_set: set) -> bool:
    """
    Check if a license is copyleft.
    
    Args:
        license_text: License identifier or text
        copyleft_set: Set of copyleft license identifiers
        
    Returns:
        True if license is copyleft, False otherwise
        
    Example:
        >>> is_copyleft_license("GPL-3.0", COPYLEFT_LICENSES)
        True
    """
    if not license_text or license_text.lower() == 'unknown':
        return False
    
    license_upper = license_text.upper()
    return any(lic in license_upper for lic in copyleft_set)


def get_severity_from_score(score: float) -> str:
    """
    Determine severity level from CVSS score.
    
    Args:
        score: CVSS score (0.0 - 10.0)
        
    Returns:
        Severity level string
        
    Example:
        >>> get_severity_from_score(9.8)
        'HIGH'
    """
    from .constants import CVSSSeverity
    
    if score >= CVSSSeverity.CRITICAL_THRESHOLD:
        return "CRITICAL"
    elif score >= CVSSSeverity.HIGH_THRESHOLD:
        return "HIGH"
    elif score >= CVSSSeverity.MEDIUM_THRESHOLD:
        return "MEDIUM"
    elif score >= CVSSSeverity.LOW_THRESHOLD:
        return "LOW"
    else:
        return "LOW"


def get_recommendation(severity: str) -> str:
    """
    Get remediation recommendation for a severity level.
    
    Args:
        severity: Severity level
        
    Returns:
        Recommendation text
    """
    from .constants import CVSSSeverity
    return CVSSSeverity.RECOMMENDATIONS.get(severity, CVSSSeverity.RECOMMENDATIONS["UNKNOWN"])


@lru_cache(maxsize=100)
def detect_ecosystem(package_name: str) -> str:
    """
    Auto-detect package ecosystem from package name.
    
    Args:
        package_name: Package name
        
    Returns:
        Detected ecosystem
        
    Example:
        >>> detect_ecosystem("@angular/core")
        'npm'
        >>> detect_ecosystem("com.google.guava")
        'maven'
    """
    if not package_name:
        return "unknown"
    
    # NPM scoped packages
    if package_name.startswith('@'):
        return "npm"
    
    # Maven group.artifact pattern
    if '.' in package_name and ':' not in package_name:
        parts = package_name.split('.')
        if len(parts) >= 2:
            return "maven"
    
    # Maven group:artifact pattern
    if ':' in package_name:
        return "maven"
    
    # Default to PyPI for simple names
    return "pypi"


def sanitize_input(text: str, max_length: int = 1000) -> str:
    """
    Sanitize user input.
    
    Args:
        text: Input text
        max_length: Maximum allowed length
        
    Returns:
        Sanitized text
    """
    if not text:
        return ""
    
    # Truncate
    sanitized = text[:max_length]
    
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[<>"'&']', '', sanitized)
    
    return sanitized.strip()
