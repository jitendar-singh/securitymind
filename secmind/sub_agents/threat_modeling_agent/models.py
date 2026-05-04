"""
Type definitions for Threat Modeling Agent.

Generalized to support multiple frameworks (STRIDE, ATLAS, OWASP-LLM, LINDDUN, ATT&CK)
via a uniform threat shape with framework + category + technique_id.
"""

from typing import TypedDict, List, Dict, Optional, Literal


class ThreatDetails(TypedDict, total=False):
    """A single identified threat, framework-tagged."""
    threat: str
    description: str
    framework: str
    category: str
    technique_id: Optional[str]
    likelihood: Literal["High", "Medium", "Low"]
    impact: Literal["High", "Medium", "Low"]
    affected_components: List[str]
    references: Optional[List[str]]
    cross_references: Optional[List[str]]


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


class ThreatModelReport(TypedDict, total=False):
    """Complete threat modeling report — multi-framework aware."""
    overview: str
    risk_score: int
    framework_scores: Dict[str, int]
    frameworks_applied: List[str]
    framework_overviews: Dict[str, str]
    identified_threats: List[ThreatDetails]
    vulnerabilities: List[VulnerabilityDetails]
    recommendations: Recommendations
    compliance_notes: Optional[List[str]]
    dfd: Optional[str]


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

    # AI/ML extensions (signals for ATLAS / OWASP-LLM auto-detect)
    ml_model: str
    training_data_source: str
    model_endpoint: str
    model_deployment: Literal["self-hosted", "managed-api", "edge"]
    llm_provider: str
    agent_tools: List[str]

    # Privacy extensions (signals for LINDDUN auto-detect)
    data_classification: List[str]
