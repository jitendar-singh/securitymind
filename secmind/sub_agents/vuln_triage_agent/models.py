"""
Data models and type definitions for vulnerability triage agent.
"""

from typing import TypedDict, Optional, List
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    """CVSS severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"


class Ecosystem(str, Enum):
    """Supported package ecosystems."""
    PYPI = "pypi"
    NPM = "npm"
    APT = "apt"
    MAVEN = "maven"
    RUBYGEMS = "rubygems"
    NUGET = "nuget"
    UNKNOWN = "unknown"


class VulnerabilityDetails(TypedDict, total=False):
    """Detailed vulnerability information."""
    cve_id: str
    published: str
    last_modified: str
    cvss_score: float
    cvss_vector: str
    description: str
    source: str


class VulnerabilityResult(TypedDict):
    """Result of vulnerability triage."""
    severity: str
    recommendation: str
    details: VulnerabilityDetails


class LicenseResult(TypedDict):
    """Result of license check."""
    license: str
    ecosystem: str
    is_copyleft: bool


class SBOMPackage(TypedDict):
    """Package information from SBOM."""
    name: str
    license: str
    is_copyleft: bool
    version: Optional[str]


class SBOMResult(TypedDict):
    """Result of SBOM parsing."""
    status: str
    packages: List[SBOMPackage]
    error_message: Optional[str]
