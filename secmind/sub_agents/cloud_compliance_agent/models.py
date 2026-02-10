"""
Data models for Cloud Compliance Agent.

This module contains dataclasses and Pydantic models for structured data
representation throughout the cloud compliance agent.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional
from enum import Enum


# ============================================================================
# ENUMS
# ============================================================================

class Severity(str, Enum):
    """Security finding severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNSPECIFIED = "SEVERITY_UNSPECIFIED"


class FindingState(str, Enum):
    """Security finding states."""
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    STATE_UNSPECIFIED = "STATE_UNSPECIFIED"


class RecommendationPriority(str, Enum):
    """IAM recommendation priority levels."""
    P1 = "P1"  # Critical
    P2 = "P2"  # High
    P3 = "P3"  # Medium
    P4 = "P4"  # Low


class ComplianceStatus(str, Enum):
    """Compliance check status."""
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"


# ============================================================================
# GCP RESOURCE MODELS
# ============================================================================

@dataclass
class GCPResource:
    """Represents a GCP resource."""
    
    name: str
    resource_type: str
    project_id: str
    location: Optional[str] = None
    labels: dict[str, str] = field(default_factory=dict)
    create_time: Optional[datetime] = None
    update_time: Optional[datetime] = None
    additional_attributes: dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "name": self.name,
            "resource_type": self.resource_type,
            "project_id": self.project_id,
            "location": self.location,
            "labels": self.labels,
            "create_time": self.create_time.isoformat() if self.create_time else None,
            "update_time": self.update_time.isoformat() if self.update_time else None,
            "additional_attributes": self.additional_attributes,
        }


@dataclass
class ResourceInventory:
    """Collection of GCP resources."""
    
    resources: list[GCPResource] = field(default_factory=list)
    total_count: int = 0
    resource_types: dict[str, int] = field(default_factory=dict)
    projects: set[str] = field(default_factory=set)
    scan_time: datetime = field(default_factory=datetime.utcnow)
    
    def add_resource(self, resource: GCPResource) -> None:
        """Add a resource to the inventory."""
        self.resources.append(resource)
        self.total_count += 1
        self.resource_types[resource.resource_type] = (
            self.resource_types.get(resource.resource_type, 0) + 1
        )
        self.projects.add(resource.project_id)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "total_count": self.total_count,
            "resource_types": self.resource_types,
            "projects": list(self.projects),
            "scan_time": self.scan_time.isoformat(),
            "resources": [r.to_dict() for r in self.resources],
        }


# ============================================================================
# SECURITY FINDING MODELS
# ============================================================================

@dataclass
class SecuritySource:
    """Represents a Security Command Center source."""
    
    name: str
    display_name: str
    description: str
    source_id: str
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "source_id": self.source_id,
        }


@dataclass
class SecurityFinding:
    """Represents a security finding from Security Command Center."""
    
    name: str
    severity: Severity
    category: str
    description: str
    state: FindingState
    resource_name: str
    create_time: Optional[datetime] = None
    event_time: Optional[datetime] = None
    source_properties: dict[str, Any] = field(default_factory=dict)
    recommendation: Optional[str] = None
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "name": self.name,
            "severity": self.severity.value,
            "category": self.category,
            "description": self.description,
            "state": self.state.value,
            "resource_name": self.resource_name,
            "create_time": self.create_time.isoformat() if self.create_time else None,
            "event_time": self.event_time.isoformat() if self.event_time else None,
            "source_properties": self.source_properties,
            "recommendation": self.recommendation,
        }


@dataclass
class SecurityPosture:
    """Represents overall security posture."""
    
    findings: list[SecurityFinding] = field(default_factory=list)
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    active_count: int = 0
    inactive_count: int = 0
    scan_time: datetime = field(default_factory=datetime.utcnow)
    
    def calculate_summary(self) -> None:
        """Calculate summary statistics from findings."""
        self.total_findings = len(self.findings)
        self.critical_count = sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
        self.high_count = sum(1 for f in self.findings if f.severity == Severity.HIGH)
        self.medium_count = sum(1 for f in self.findings if f.severity == Severity.MEDIUM)
        self.low_count = sum(1 for f in self.findings if f.severity == Severity.LOW)
        self.info_count = sum(1 for f in self.findings if f.severity == Severity.INFO)
        self.active_count = sum(1 for f in self.findings if f.state == FindingState.ACTIVE)
        self.inactive_count = sum(1 for f in self.findings if f.state == FindingState.INACTIVE)
    
    def get_risk_score(self) -> int:
        """Calculate overall risk score based on findings."""
        score = (
            self.critical_count * 10 +
            self.high_count * 7 +
            self.medium_count * 4 +
            self.low_count * 2
        )
        return score
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "total_findings": self.total_findings,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "info_count": self.info_count,
            "active_count": self.active_count,
            "inactive_count": self.inactive_count,
            "risk_score": self.get_risk_score(),
            "scan_time": self.scan_time.isoformat(),
            "findings": [f.to_dict() for f in self.findings],
        }


# ============================================================================
# IAM MODELS
# ============================================================================

@dataclass
class IAMRecommendation:
    """Represents an IAM recommendation."""
    
    name: str
    description: str
    priority: RecommendationPriority
    recommender_subtype: Optional[str] = None
    content: dict[str, Any] = field(default_factory=dict)
    state_info: dict[str, Any] = field(default_factory=dict)
    last_refresh_time: Optional[datetime] = None
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "name": self.name,
            "description": self.description,
            "priority": self.priority.value,
            "recommender_subtype": self.recommender_subtype,
            "content": self.content,
            "state_info": self.state_info,
            "last_refresh_time": self.last_refresh_time.isoformat() if self.last_refresh_time else None,
        }


@dataclass
class ServiceAccountKey:
    """Represents a service account key."""
    
    key_name: str
    service_account: str
    create_time: datetime
    age_days: int
    key_algorithm: Optional[str] = None
    key_type: Optional[str] = None
    valid_after_time: Optional[datetime] = None
    valid_before_time: Optional[datetime] = None
    
    def is_compliant(self, max_age_days: int = 90) -> bool:
        """Check if key rotation is compliant."""
        return self.age_days <= max_age_days
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "key_name": self.key_name,
            "service_account": self.service_account,
            "create_time": self.create_time.isoformat(),
            "age_days": self.age_days,
            "key_algorithm": self.key_algorithm,
            "key_type": self.key_type,
            "valid_after_time": self.valid_after_time.isoformat() if self.valid_after_time else None,
            "valid_before_time": self.valid_before_time.isoformat() if self.valid_before_time else None,
        }


@dataclass
class MFAStatus:
    """Represents MFA status for a user."""
    
    user_email: str
    mfa_enabled: bool
    is_privileged: bool
    is_admin: bool = False
    is_delegated_admin: bool = False
    enrollment_date: Optional[datetime] = None
    
    def is_compliant(self) -> bool:
        """Check if MFA status is compliant."""
        if self.is_privileged:
            return self.mfa_enabled
        return True  # Non-privileged users are compliant regardless
    
    def get_status_note(self) -> str:
        """Get human-readable status note."""
        if self.is_privileged and not self.mfa_enabled:
            return "CRITICAL: Privileged user without MFA"
        elif self.is_privileged and self.mfa_enabled:
            return "Compliant: Privileged user with MFA"
        elif not self.is_privileged and self.mfa_enabled:
            return "Good: MFA enabled"
        else:
            return "Acceptable: Non-privileged user without MFA"
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "user_email": self.user_email,
            "mfa_enabled": self.mfa_enabled,
            "is_privileged": self.is_privileged,
            "is_admin": self.is_admin,
            "is_delegated_admin": self.is_delegated_admin,
            "enrollment_date": self.enrollment_date.isoformat() if self.enrollment_date else None,
            "is_compliant": self.is_compliant(),
            "status_note": self.get_status_note(),
        }


# ============================================================================
# ORGANIZATION POLICY MODELS
# ============================================================================

@dataclass
class OrganizationPolicy:
    """Represents an organization policy."""
    
    name: str
    constraint: str
    rules: list[dict[str, Any]] = field(default_factory=list)
    etag: Optional[str] = None
    update_time: Optional[datetime] = None
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "name": self.name,
            "constraint": self.constraint,
            "rules": self.rules,
            "etag": self.etag,
            "update_time": self.update_time.isoformat() if self.update_time else None,
        }


@dataclass
class PolicyCompliance:
    """Represents policy compliance status."""
    
    policy_name: str
    status: ComplianceStatus
    details: str
    recommendation: Optional[str] = None
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "policy_name": self.policy_name,
            "status": self.status.value,
            "details": self.details,
            "recommendation": self.recommendation,
        }


# ============================================================================
# REPORT MODELS
# ============================================================================

@dataclass
class ComplianceReport:
    """Comprehensive compliance report."""
    
    report_id: str
    generated_at: datetime = field(default_factory=datetime.utcnow)
    project_id: Optional[str] = None
    organization_id: Optional[str] = None
    
    # Report sections
    resource_inventory: Optional[ResourceInventory] = None
    security_posture: Optional[SecurityPosture] = None
    iam_recommendations: list[IAMRecommendation] = field(default_factory=list)
    organization_policies: list[OrganizationPolicy] = field(default_factory=list)
    service_account_keys: list[ServiceAccountKey] = field(default_factory=list)
    mfa_status: list[MFAStatus] = field(default_factory=list)
    policy_compliance: list[PolicyCompliance] = field(default_factory=list)
    
    # Summary statistics
    overall_risk_score: int = 0
    compliance_percentage: float = 0.0
    critical_issues_count: int = 0
    
    def calculate_summary(self) -> None:
        """Calculate summary statistics."""
        if self.security_posture:
            self.overall_risk_score = self.security_posture.get_risk_score()
            self.critical_issues_count = self.security_posture.critical_count
        
        # Calculate compliance percentage
        total_checks = 0
        compliant_checks = 0
        
        if self.service_account_keys:
            total_checks += len(self.service_account_keys)
            compliant_checks += sum(1 for k in self.service_account_keys if k.is_compliant())
        
        if self.mfa_status:
            total_checks += len(self.mfa_status)
            compliant_checks += sum(1 for m in self.mfa_status if m.is_compliant())
        
        if total_checks > 0:
            self.compliance_percentage = (compliant_checks / total_checks) * 100
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "report_id": self.report_id,
            "generated_at": self.generated_at.isoformat(),
            "project_id": self.project_id,
            "organization_id": self.organization_id,
            "overall_risk_score": self.overall_risk_score,
            "compliance_percentage": self.compliance_percentage,
            "critical_issues_count": self.critical_issues_count,
            "resource_inventory": self.resource_inventory.to_dict() if self.resource_inventory else None,
            "security_posture": self.security_posture.to_dict() if self.security_posture else None,
            "iam_recommendations": [r.to_dict() for r in self.iam_recommendations],
            "organization_policies": [p.to_dict() for p in self.organization_policies],
            "service_account_keys": [k.to_dict() for k in self.service_account_keys],
            "mfa_status": [m.to_dict() for m in self.mfa_status],
            "policy_compliance": [p.to_dict() for p in self.policy_compliance],
        }


# ============================================================================
# API RESPONSE MODELS
# ============================================================================

@dataclass
class APIResponse:
    """Standard API response wrapper."""
    
    status: str  # "success" or "error"
    data: Optional[Any] = None
    message: Optional[str] = None
    error_details: Optional[dict[str, Any]] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        result = {
            "status": self.status,
            "timestamp": self.timestamp.isoformat(),
        }
        
        if self.data is not None:
            # Handle dataclass conversion
            if hasattr(self.data, 'to_dict'):
                result["data"] = self.data.to_dict()
            elif isinstance(self.data, list) and self.data and hasattr(self.data[0], 'to_dict'):
                result["data"] = [item.to_dict() for item in self.data]
            else:
                result["data"] = self.data
        
        if self.message:
            result["message"] = self.message
        
        if self.error_details:
            result["error_details"] = self.error_details
        
        return result
    
    @classmethod
    def success(cls, data: Any = None, message: Optional[str] = None) -> "APIResponse":
        """Create a success response."""
        return cls(status="success", data=data, message=message)
    
    @classmethod
    def error(cls, message: str, error_details: Optional[dict[str, Any]] = None) -> "APIResponse":
        """Create an error response."""
        return cls(status="error", message=message, error_details=error_details)
