"""
Type definitions for Application Security Agent.
"""

from typing import TypedDict, List, Dict, Optional, Literal


class ThreatDetails(TypedDict):
    """Details of an identified threat."""
    threat: str
    description: str
    stride_category: str
    likelihood: Literal["High", "Medium", "Low"]
    impact: Literal["High", "Medium", "Low"]
    affected_components: List[str]


class VulnerabilityDetails(TypedDict):
    """Details of an identified vulnerability."""
    vulnerability: str
    description: str
    severity: Literal["Critical", "High", "Medium", "Low", "Info"]
    component: str
    cwe_id: Optional[str]
    remediation: str


class Recommendations(TypedDict, total=False):
    """Security recommendations by category."""
    authentication: List[str]
    authorization: List[str]
    data_protection: List[str]
    cloud_security: List[str]
    networking: List[str]
    input_validation: List[str]
    logging_monitoring: List[str]
    general: List[str]


class ThreatModelReport(TypedDict):
    """Complete threat modeling report."""
    overview: str
    risk_score: int  # 0-100
    identified_threats: List[ThreatDetails]
    vulnerabilities: List[VulnerabilityDetails]
    recommendations: Recommendations
    compliance_notes: Optional[List[str]]


class ThreatModelResult(TypedDict):
    """Result from threat modeling operation."""
    status: Literal["success", "error"]
    report: Optional[ThreatModelReport]
    message: Optional[str]


class ApplicationDetails(TypedDict, total=False):
    """Application details for threat modeling."""
    framework: str
    language: str
    networking: str
    deployment_env: str
    cloud_provider: str
    cloud_config: str
    authentication: str
    authorization: str
    data_storage: str
    apis: str
    third_party_services: str
    compliance_requirements: List[str]
    existing_security_controls: List[str]
