"""
GCP API Client with error handling, retries, and logging.

This module provides a robust wrapper around GCP APIs with:
- Automatic retry logic with exponential backoff
- Comprehensive error handling
- Logging and monitoring
- Rate limiting
- Timeout management
"""

import logging
import time
from functools import wraps
from typing import Any, Callable, Optional, TypeVar, cast
from datetime import datetime, timezone

from google.cloud import asset_v1
from google.cloud import securitycenter_v1
from google.cloud import recommender_v1
from google.cloud import orgpolicy_v2
from google.cloud import iam_admin_v1
from google.api_core import exceptions as gcp_exceptions
from google.api_core import retry
from google.protobuf.json_format import MessageToDict
from googleapiclient.discovery import build
from google.oauth2 import service_account

from .constants import (
    DEFAULT_API_TIMEOUT,
    MAX_RETRIES,
    RETRY_BACKOFF_FACTOR,
    RETRY_INITIAL_DELAY,
    ErrorMessage,
)
from .models import APIResponse

# Configure logging
logger = logging.getLogger(__name__)

# Type variable for generic retry decorator
T = TypeVar('T')


# ============================================================================
# DECORATORS
# ============================================================================

def retry_on_failure(
    max_retries: int = MAX_RETRIES,
    backoff_factor: float = RETRY_BACKOFF_FACTOR,
    initial_delay: float = RETRY_INITIAL_DELAY,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator to retry function on failure with exponential backoff.
    
    Args:
        max_retries: Maximum number of retry attempts
        backoff_factor: Multiplier for exponential backoff
        initial_delay: Initial delay in seconds
    
    Returns:
        Decorated function with retry logic
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            delay = initial_delay
            last_exception = None
            
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except (
                    gcp_exceptions.ServiceUnavailable,
                    gcp_exceptions.DeadlineExceeded,
                    gcp_exceptions.ResourceExhausted,
                ) as e:
                    last_exception = e
                    if attempt < max_retries:
                        logger.warning(
                            f"Attempt {attempt + 1}/{max_retries + 1} failed for {func.__name__}: {e}. "
                            f"Retrying in {delay:.2f}s..."
                        )
                        time.sleep(delay)
                        delay *= backoff_factor
                    else:
                        logger.error(f"All {max_retries + 1} attempts failed for {func.__name__}")
                except Exception as e:
                    # Don't retry on other exceptions
                    logger.error(f"Non-retryable error in {func.__name__}: {e}")
                    raise
            
            # If we get here, all retries failed
            raise last_exception or Exception("Unknown error in retry logic")
        
        return wrapper
    return decorator


def handle_gcp_errors(func: Callable[..., APIResponse]) -> Callable[..., APIResponse]:
    """
    Decorator to handle GCP API errors and return standardized responses.
    
    Args:
        func: Function to decorate
    
    Returns:
        Decorated function with error handling
    """
    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> APIResponse:
        try:
            return func(*args, **kwargs)
        except gcp_exceptions.PermissionDenied as e:
            logger.error(f"Permission denied in {func.__name__}: {e}")
            return APIResponse.error(
                message=ErrorMessage.ACCESS_DENIED.format(resource=str(e)),
                error_details={"error_type": "PermissionDenied", "details": str(e)}
            )
        except gcp_exceptions.NotFound as e:
            logger.error(f"Resource not found in {func.__name__}: {e}")
            return APIResponse.error(
                message=ErrorMessage.RESOURCE_NOT_FOUND.format(resource=str(e)),
                error_details={"error_type": "NotFound", "details": str(e)}
            )
        except gcp_exceptions.InvalidArgument as e:
            logger.error(f"Invalid argument in {func.__name__}: {e}")
            return APIResponse.error(
                message=f"Invalid argument: {e}",
                error_details={"error_type": "InvalidArgument", "details": str(e)}
            )
        except gcp_exceptions.DeadlineExceeded as e:
            logger.error(f"Timeout in {func.__name__}: {e}")
            return APIResponse.error(
                message=ErrorMessage.API_TIMEOUT.format(timeout=DEFAULT_API_TIMEOUT),
                error_details={"error_type": "DeadlineExceeded", "details": str(e)}
            )
        except gcp_exceptions.ResourceExhausted as e:
            logger.error(f"Rate limit exceeded in {func.__name__}: {e}")
            return APIResponse.error(
                message=ErrorMessage.API_RATE_LIMIT,
                error_details={"error_type": "ResourceExhausted", "details": str(e)}
            )
        except Exception as e:
            logger.exception(f"Unexpected error in {func.__name__}: {e}")
            return APIResponse.error(
                message=ErrorMessage.UNEXPECTED_ERROR.format(error=str(e)),
                error_details={"error_type": type(e).__name__, "details": str(e)}
            )
    
    return wrapper


# ============================================================================
# GCP CLIENT CLASS
# ============================================================================

class GCPClient:
    """
    Robust GCP API client with error handling and retry logic.
    
    This class provides methods to interact with various GCP APIs:
    - Asset Inventory API
    - Security Command Center API
    - IAM Recommender API
    - Organization Policy API
    - IAM Admin API
    - Admin SDK API
    """
    
    def __init__(
        self,
        credentials_path: Optional[str] = None,
        timeout: int = DEFAULT_API_TIMEOUT
    ):
        """
        Initialize GCP client.
        
        Args:
            credentials_path: Path to service account credentials JSON file
            timeout: Default timeout for API calls in seconds
        """
        self.credentials_path = credentials_path
        self.timeout = timeout
        self._clients: dict[str, Any] = {}
        
        logger.info("GCP Client initialized")
    
    def _get_client(self, client_type: str) -> Any:
        """
        Get or create a GCP API client.
        
        Args:
            client_type: Type of client to create
        
        Returns:
            GCP API client instance
        """
        if client_type not in self._clients:
            try:
                if client_type == "asset":
                    self._clients[client_type] = asset_v1.AssetServiceClient()
                elif client_type == "security_center":
                    self._clients[client_type] = securitycenter_v1.SecurityCenterClient()
                elif client_type == "recommender":
                    self._clients[client_type] = recommender_v1.RecommenderClient()
                elif client_type == "org_policy":
                    self._clients[client_type] = orgpolicy_v2.OrgPolicyClient()
                elif client_type == "iam_admin":
                    self._clients[client_type] = iam_admin_v1.IAMClient()
                else:
                    raise ValueError(f"Unknown client type: {client_type}")
                
                logger.debug(f"Created {client_type} client")
            except Exception as e:
                logger.error(f"Failed to create {client_type} client: {e}")
                raise
        
        return self._clients[client_type]
    
    # ========================================================================
    # ASSET INVENTORY METHODS
    # ========================================================================
    
    @handle_gcp_errors
    @retry_on_failure()
    def list_resources(
        self,
        scope: str,
        asset_types: Optional[list[str]] = None,
        page_size: int = 100
    ) -> APIResponse:
        """
        List GCP resources using Asset Inventory API.
        
        Args:
            scope: Scope to search (e.g., "projects/my-project")
            asset_types: List of asset types to filter (None for all)
            page_size: Number of results per page
        
        Returns:
            APIResponse with list of resources
        """
        logger.info(f"Listing resources for scope: {scope}")
        
        client = self._get_client("asset")
        
        request = {
            "scope": scope,
            "page_size": page_size,
        }
        
        if asset_types:
            request["asset_types"] = asset_types
        
        resources = []
        response = client.search_all_resources(request=request)
        
        for item in response:
            resource_dict = MessageToDict(item._pb)
            resources.append(resource_dict)
        
        logger.info(f"Found {len(resources)} resources")
        
        return APIResponse.success(
            data=resources,
            message=f"Successfully listed {len(resources)} resources"
        )
    
    # ========================================================================
    # SECURITY COMMAND CENTER METHODS
    # ========================================================================
    
    @handle_gcp_errors
    @retry_on_failure()
    def list_security_sources(self, parent: str) -> APIResponse:
        """
        List security sources in Security Command Center.
        
        Args:
            parent: Parent resource (e.g., "organizations/123")
        
        Returns:
            APIResponse with list of security sources
        """
        logger.info(f"Listing security sources for: {parent}")
        
        client = self._get_client("security_center")
        
        sources = []
        for source in client.list_sources(request={"parent": parent}):
            sources.append({
                "name": source.name,
                "display_name": source.display_name,
                "description": source.description,
                "source_id": source.name.split('/')[-1],
            })
        
        logger.info(f"Found {len(sources)} security sources")
        
        return APIResponse.success(
            data=sources,
            message=f"Found {len(sources)} security sources"
        )
    
    @handle_gcp_errors
    @retry_on_failure()
    def list_findings(
        self,
        parent: str,
        source_id: Optional[str] = None,
        page_size: int = 100
    ) -> APIResponse:
        """
        List security findings from Security Command Center.
        
        Args:
            parent: Parent resource (e.g., "organizations/123" or "projects/my-project")
            source_id: Specific source ID to filter (None for all sources)
            page_size: Number of results per page
        
        Returns:
            APIResponse with list of findings and summary
        """
        source_parent = f"{parent}/sources/{source_id if source_id else '-'}"
        logger.info(f"Listing findings for: {source_parent}")
        
        client = self._get_client("security_center")
        
        request = {
            "parent": source_parent,
            "page_size": page_size,
        }
        
        findings = []
        response = client.list_findings(request=request)
        
        for result in response:
            finding = result.finding
            findings.append({
                "name": finding.name,
                "severity": finding.severity.name if finding.severity else "UNSPECIFIED",
                "category": finding.category,
                "description": finding.description if hasattr(finding, 'description') else "",
                "state": finding.state.name if finding.state else "UNSPECIFIED",
                "resource_name": finding.resource_name,
                "create_time": finding.create_time.isoformat() if finding.create_time else None,
                "event_time": finding.event_time.isoformat() if finding.event_time else None,
            })
        
        # Calculate summary
        summary = {
            "total_findings": len(findings),
            "critical_count": sum(1 for f in findings if f['severity'] == 'CRITICAL'),
            "high_count": sum(1 for f in findings if f['severity'] == 'HIGH'),
            "medium_count": sum(1 for f in findings if f['severity'] == 'MEDIUM'),
            "low_count": sum(1 for f in findings if f['severity'] == 'LOW'),
        }
        
        logger.info(f"Found {len(findings)} findings")
        
        return APIResponse.success(
            data={"findings": findings, "summary": summary},
            message=f"Retrieved {len(findings)} security findings"
        )
    
    # ========================================================================
    # IAM RECOMMENDER METHODS
    # ========================================================================
    
    @handle_gcp_errors
    @retry_on_failure()
    def list_iam_recommendations(
        self,
        project_id: str,
        recommender_id: str = "google.iam.policy.Recommender"
    ) -> APIResponse:
        """
        List IAM recommendations for least privilege.
        
        Args:
            project_id: GCP project ID
            recommender_id: Recommender ID
        
        Returns:
            APIResponse with list of recommendations
        """
        parent = f"projects/{project_id}/locations/global/recommenders/{recommender_id}"
        logger.info(f"Listing IAM recommendations for: {parent}")
        
        client = self._get_client("recommender")
        
        recommendations = []
        for reco in client.list_recommendations(parent=parent):
            recommendations.append({
                "name": reco.name,
                "description": reco.description,
                "priority": reco.priority.name if reco.priority else "UNSPECIFIED",
                "recommender_subtype": reco.recommender_subtype,
                "last_refresh_time": reco.last_refresh_time.isoformat() if reco.last_refresh_time else None,
            })
        
        logger.info(f"Found {len(recommendations)} IAM recommendations")
        
        return APIResponse.success(
            data=recommendations,
            message=f"{len(recommendations)} IAM recommendations found"
        )
    
    # ========================================================================
    # ORGANIZATION POLICY METHODS
    # ========================================================================
    
    @handle_gcp_errors
    @retry_on_failure()
    def list_org_policies(self, parent: str) -> APIResponse:
        """
        List organization policies.
        
        Args:
            parent: Parent resource (e.g., "organizations/123")
        
        Returns:
            APIResponse with list of policies
        """
        logger.info(f"Listing organization policies for: {parent}")
        
        client = self._get_client("org_policy")
        
        policies = []
        for policy in client.list_policies(parent=parent):
            policies.append({
                "name": policy.name,
                "constraint": policy.name.split('/')[-1],
                "rules": [MessageToDict(rule._pb) for rule in policy.spec.rules] if policy.spec and policy.spec.rules else [],
                "etag": policy.spec.etag if policy.spec else None,
            })
        
        logger.info(f"Found {len(policies)} organization policies")
        
        return APIResponse.success(
            data=policies,
            message=f"{len(policies)} policies listed"
        )
    
    # ========================================================================
    # IAM ADMIN METHODS
    # ========================================================================
    
    @handle_gcp_errors
    @retry_on_failure()
    def list_service_account_keys(
        self,
        project_id: str,
        max_age_days: int = 90
    ) -> APIResponse:
        """
        List and check service account keys for rotation.
        
        Args:
            project_id: GCP project ID
            max_age_days: Maximum age in days for compliance
        
        Returns:
            APIResponse with list of keys and compliance status
        """
        logger.info(f"Listing service account keys for project: {project_id}")
        
        client = self._get_client("iam_admin")
        
        keys = []
        non_compliant = []
        
        # List all service accounts
        for sa in client.list_service_accounts(request={"name": f"projects/{project_id}"}):
            sa_name = sa.name
            
            # List keys for this service account
            request = iam_admin_v1.ListServiceAccountKeysRequest(name=sa_name)
            response = client.list_service_account_keys(request=request)
            
            for key in response.keys:
                if not key.valid_after_time:
                    continue
                
                create_time = key.valid_after_time
                age_days = (datetime.now(timezone.utc) - create_time).days
                
                key_info = {
                    "key_name": key.name,
                    "service_account": sa_name,
                    "create_time": create_time.isoformat(),
                    "age_days": age_days,
                    "key_algorithm": key.key_algorithm.name if key.key_algorithm else None,
                    "key_type": key.key_type.name if key.key_type else None,
                }
                
                keys.append(key_info)
                
                if age_days > max_age_days:
                    non_compliant.append(key_info)
        
        logger.info(f"Found {len(keys)} keys, {len(non_compliant)} non-compliant")
        
        return APIResponse.success(
            data={
                "keys": keys,
                "non_compliant": non_compliant,
                "summary": f"{len(non_compliant)} keys older than {max_age_days} days"
            },
            message=f"Analyzed {len(keys)} service account keys"
        )
