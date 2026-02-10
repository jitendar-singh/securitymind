"""
Constants for Cloud Compliance Agent.

This module contains all constants, error messages, defaults, and configuration
values used throughout the cloud compliance agent.
"""

from enum import Enum
from typing import Final

# ============================================================================
# API CONFIGURATION
# ============================================================================

# Default timeouts (in seconds)
DEFAULT_API_TIMEOUT: Final[int] = 30
DEFAULT_LONG_OPERATION_TIMEOUT: Final[int] = 300

# Retry configuration
MAX_RETRIES: Final[int] = 3
RETRY_BACKOFF_FACTOR: Final[float] = 2.0
RETRY_INITIAL_DELAY: Final[float] = 1.0

# Rate limiting
DEFAULT_RATE_LIMIT_CALLS: Final[int] = 100
DEFAULT_RATE_LIMIT_PERIOD: Final[int] = 60  # seconds

# ============================================================================
# COMPLIANCE THRESHOLDS
# ============================================================================

# Access key rotation
DEFAULT_MAX_KEY_AGE_DAYS: Final[int] = 90
RECOMMENDED_MAX_KEY_AGE_DAYS: Final[int] = 30
CRITICAL_MAX_KEY_AGE_DAYS: Final[int] = 180

# Password policy
MIN_PASSWORD_LENGTH: Final[int] = 12
RECOMMENDED_PASSWORD_LENGTH: Final[int] = 16
REQUIRE_PASSWORD_COMPLEXITY: Final[bool] = True
MAX_PASSWORD_AGE_DAYS: Final[int] = 90

# Session configuration
MAX_SESSION_DURATION_HOURS: Final[int] = 12
IDLE_SESSION_TIMEOUT_MINUTES: Final[int] = 30

# ============================================================================
# GCP RESOURCE TYPES
# ============================================================================

class GCPResourceType(str, Enum):
    """Supported GCP resource types for inventory."""
    
    ALL = "all"
    COMPUTE_INSTANCE = "compute.googleapis.com/Instance"
    STORAGE_BUCKET = "storage.googleapis.com/Bucket"
    SQL_INSTANCE = "sqladmin.googleapis.com/Instance"
    SERVICE_ACCOUNT = "iam.googleapis.com/ServiceAccount"
    NETWORK = "compute.googleapis.com/Network"
    FIREWALL = "compute.googleapis.com/Firewall"
    KMS_KEY = "cloudkms.googleapis.com/CryptoKey"
    PUBSUB_TOPIC = "pubsub.googleapis.com/Topic"
    CLOUD_FUNCTION = "cloudfunctions.googleapis.com/CloudFunction"
    GKE_CLUSTER = "container.googleapis.com/Cluster"


# ============================================================================
# SEVERITY LEVELS
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


# ============================================================================
# IAM CONFIGURATION
# ============================================================================

# IAM Recommender types
IAM_RECOMMENDER_ID: Final[str] = "google.iam.policy.Recommender"
IAM_BINDING_RECOMMENDER_ID: Final[str] = "google.iam.policy.Recommender"

# Admin SDK scopes
ADMIN_SDK_USER_SCOPE: Final[str] = "https://www.googleapis.com/auth/admin.directory.user"
ADMIN_SDK_GROUP_SCOPE: Final[str] = "https://www.googleapis.com/auth/admin.directory.group"

# ============================================================================
# ORGANIZATION POLICY CONSTRAINTS
# ============================================================================

CRITICAL_ORG_POLICIES: Final[list[str]] = [
    "constraints/storage.uniformBucketLevelAccess",
    "constraints/storage.publicAccessPrevention",
    "constraints/iam.disableServiceAccountKeyCreation",
    "constraints/compute.requireShieldedVm",
    "constraints/compute.requireOsLogin",
    "constraints/sql.restrictPublicIp",
]

# ============================================================================
# ERROR MESSAGES
# ============================================================================

class ErrorMessage:
    """Standard error messages."""
    
    # Authentication errors
    AUTH_FAILED = "Authentication failed. Please check credentials."
    CREDENTIALS_NOT_FOUND = "Credentials file not found: {path}"
    INVALID_CREDENTIALS = "Invalid credentials format or content."
    
    # API errors
    API_CALL_FAILED = "API call failed: {error}"
    API_TIMEOUT = "API call timed out after {timeout} seconds."
    API_RATE_LIMIT = "API rate limit exceeded. Please retry later."
    
    # Input validation errors
    INVALID_PROJECT_ID = "Invalid project ID: {project_id}"
    INVALID_ORG_ID = "Invalid organization ID: {org_id}"
    INVALID_FOLDER_ID = "Invalid folder ID: {folder_id}"
    MISSING_REQUIRED_PARAM = "Missing required parameter: {param}"
    INVALID_RESOURCE_TYPE = "Invalid resource type: {resource_type}"
    
    # Resource errors
    RESOURCE_NOT_FOUND = "Resource not found: {resource}"
    ACCESS_DENIED = "Access denied to resource: {resource}"
    
    # General errors
    UNEXPECTED_ERROR = "An unexpected error occurred: {error}"
    OPERATION_FAILED = "Operation failed: {operation}"


# ============================================================================
# SUCCESS MESSAGES
# ============================================================================

class SuccessMessage:
    """Standard success messages."""
    
    RESOURCES_LISTED = "Successfully listed {count} resources."
    FINDINGS_RETRIEVED = "Retrieved {count} security findings."
    RECOMMENDATIONS_FOUND = "Found {count} IAM recommendations."
    POLICIES_CHECKED = "Checked {count} organization policies."
    KEYS_ANALYZED = "Analyzed {count} service account keys."
    MFA_STATUS_CHECKED = "Checked MFA status for {count} users."


# ============================================================================
# REPORT CONFIGURATION
# ============================================================================

# Report sections
REPORT_SECTION_SUMMARY: Final[str] = "Executive Summary"
REPORT_SECTION_RESOURCES: Final[str] = "GCP Resources Inventory"
REPORT_SECTION_SECURITY: Final[str] = "Security Posture"
REPORT_SECTION_IAM: Final[str] = "IAM Controls"
REPORT_SECTION_POLICIES: Final[str] = "Organization Policies"
REPORT_SECTION_KEYS: Final[str] = "Access Key Rotation"
REPORT_SECTION_MFA: Final[str] = "MFA and Password Policy"
REPORT_SECTION_RECOMMENDATIONS: Final[str] = "Recommendations"

# Report formatting
REPORT_MAX_FINDINGS_DETAIL: Final[int] = 50
REPORT_MAX_RECOMMENDATIONS_DETAIL: Final[int] = 20

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

LOG_FORMAT: Final[str] = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_DATE_FORMAT: Final[str] = "%Y-%m-%d %H:%M:%S"

# ============================================================================
# VALIDATION PATTERNS
# ============================================================================

import re

# GCP resource naming patterns
PROJECT_ID_PATTERN: Final[re.Pattern] = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
ORG_ID_PATTERN: Final[re.Pattern] = re.compile(r"^[0-9]{1,19}$")
FOLDER_ID_PATTERN: Final[re.Pattern] = re.compile(r"^[0-9]{1,19}$")

# Email pattern for domain validation
EMAIL_PATTERN: Final[re.Pattern] = re.compile(
    r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
)

# ============================================================================
# CACHE CONFIGURATION
# ============================================================================

# Cache TTL (Time To Live) in seconds
CACHE_TTL_SHORT: Final[int] = 300  # 5 minutes
CACHE_TTL_MEDIUM: Final[int] = 1800  # 30 minutes
CACHE_TTL_LONG: Final[int] = 3600  # 1 hour

# Cache size limits
MAX_CACHE_SIZE: Final[int] = 1000

# ============================================================================
# PAGINATION
# ============================================================================

DEFAULT_PAGE_SIZE: Final[int] = 100
MAX_PAGE_SIZE: Final[int] = 1000

# ============================================================================
# COMPLIANCE FRAMEWORKS
# ============================================================================

class ComplianceFramework(str, Enum):
    """Supported compliance frameworks."""
    
    CIS_GCP = "CIS Google Cloud Platform Foundation Benchmark"
    PCI_DSS = "PCI-DSS"
    HIPAA = "HIPAA"
    SOC2 = "SOC 2"
    ISO27001 = "ISO 27001"
    NIST_CSF = "NIST Cybersecurity Framework"


# ============================================================================
# RISK SCORING
# ============================================================================

RISK_SCORE_CRITICAL: Final[int] = 10
RISK_SCORE_HIGH: Final[int] = 7
RISK_SCORE_MEDIUM: Final[int] = 4
RISK_SCORE_LOW: Final[int] = 2
RISK_SCORE_INFO: Final[int] = 0

# ============================================================================
# EXPORT FORMATS
# ============================================================================

class ExportFormat(str, Enum):
    """Supported export formats for reports."""
    
    JSON = "json"
    CSV = "csv"
    PDF = "pdf"
    HTML = "html"
    MARKDOWN = "markdown"
