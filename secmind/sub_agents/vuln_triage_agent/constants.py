"""
Constants and configuration for vulnerability triage agent.

This module centralizes all constants, API URLs, and configuration values.
"""

from typing import Set

# License Classifications
COPYLEFT_LICENSES: Set[str] = {
    "GPL", "GPL-2.0", "GPL-3.0",
    "AGPL", "AGPL-3.0",
    "LGPL", "LGPL-2.1", "LGPL-3.0",
    "MPL", "MPL-2.0",
    "EPL", "EPL-1.0", "EPL-2.0",
    "CDDL", "CDDL-1.0"
}

# API Endpoints
class APIEndpoints:
    """API endpoint URLs for external services."""
    
    CVE_ORG = "https://cveawg.mitre.org/api/cve/{cve_id}"
    PYPI = "https://pypi.org/pypi/{package}/json"
    NPM = "https://registry.npmjs.org/{package}"
    MAVEN_CENTRAL = "https://search.maven.org/solrsearch/select"
    CLEARLY_DEFINED = "https://api.clearlydefined.io/definitions/{ecosystem}/{package}"
    
# HTTP Configuration
class HTTPConfig:
    """HTTP client configuration."""
    
    TIMEOUT = 10  # seconds
    MAX_RETRIES = 3
    RETRY_DELAY = 1  # seconds
    BACKOFF_FACTOR = 2
    
# CVSS Severity Thresholds
class CVSSSeverity:
    """CVSS severity level thresholds and recommendations."""
    
    CRITICAL_THRESHOLD = 9.5
    HIGH_THRESHOLD = 9.0
    MEDIUM_THRESHOLD = 7.0
    LOW_THRESHOLD = 4.0
    
    RECOMMENDATIONS = {
        "CRITICAL": "Patch immediately - critical security risk.",
        "HIGH": "Patch immediately - high security risk.",
        "MEDIUM": "Patch within 30 days.",
        "LOW": "Monitor and patch as needed.",
        "UNKNOWN": "Review for applicability."
    }

# Cache Configuration
class CacheConfig:
    """Cache configuration for API results."""
    
    ENABLED = True
    TTL_SECONDS = 3600  # 1 hour
    MAX_SIZE = 1000  # Maximum cached items
