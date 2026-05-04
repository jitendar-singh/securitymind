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
from google.cloud import compute_v1
from google.api_core import exceptions as gcp_exceptions
from google.api_core import retry
from google.protobuf.json_format import MessageToDict
from googleapiclient.discovery import build
from google.oauth2 import service_account

from ..constants import (
    DEFAULT_API_TIMEOUT,
    MAX_RETRIES,
    RETRY_BACKOFF_FACTOR,
    RETRY_INITIAL_DELAY,
    ErrorMessage,
)
from ..models import APIResponse
from .base import BaseClient

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

class GCPClient(BaseClient):
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
                elif client_type == "storage":
                    from google.cloud import storage
                    self._clients[client_type] = storage.Client()
                elif client_type == "compute_subnetworks":
                    self._clients[client_type] = compute_v1.SubnetworksClient()
                elif client_type == "compute_networks":
                    self._clients[client_type] = compute_v1.NetworksClient()
                elif client_type == "compute_security_policies":
                    self._clients[client_type] = compute_v1.SecurityPoliciesClient()
                elif client_type == "compute_backend_services":
                    self._clients[client_type] = compute_v1.BackendServicesClient()
                elif client_type == "kms":
                    from google.cloud import kms_v1
                    self._clients[client_type] = kms_v1.KeyManagementServiceClient()
                elif client_type == "secret_manager":
                    from google.cloud import secretmanager_v1
                    self._clients[client_type] = secretmanager_v1.SecretManagerServiceClient()
                elif client_type == "dns":
                    # Use discovery — no first-class google-cloud-dns Python client.
                    self._clients[client_type] = build("dns", "v1", cache_discovery=False)
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
        recommender_id: Optional[str] = "google.iam.policy.Recommender"
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
            details = {"operations": []}
            try:
                content = MessageToDict(reco.content._pb)
                if 'operationGroups' in content and content['operationGroups']:
                    for op_group in content['operationGroups']:
                        operations = op_group.get('operations', [])
                        for op in operations:
                            op_details = {
                                "action": op.get("action"),
                                "resource": op.get("resource"),
                                "path": op.get("path"),
                                "op": op.get("op"),
                                "value": op.get("value"),
                                "originalValue": op.get("originalValue"),
                                "pathFilters": op.get("pathFilters"),
                            }
                            details["operations"].append(op_details)
                if not details["operations"]:
                    if reco.description:
                        details['summary'] = reco.description
            except Exception as e:
                logger.warning(f"Could not parse details for recommendation {reco.name}: {e}")

            recommendations.append({
                "name": reco.name,
                "description": reco.description,
                "priority": reco.priority.name if reco.priority else "UNSPECIFIED",
                "recommender_subtype": reco.recommender_subtype,
                "last_refresh_time": reco.last_refresh_time.isoformat() if reco.last_refresh_time else None,
                "details": details,
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

    # ========================================================================
    # GCS METHODS
    # ========================================================================

    @handle_gcp_errors
    @retry_on_failure()
    def list_public_gcs_buckets(self, project_id: str) -> APIResponse:
        """
        List publicly accessible GCS buckets.

        Args:
            project_id: GCP project ID

        Returns:
            APIResponse with list of public buckets and summary
        """
        logger.info(f"Listing public GCS buckets for project: {project_id}")

        storage_client = self._get_client("storage")
        
        public_buckets = []
        
        for bucket in storage_client.list_buckets(project=project_id):
            policy = bucket.get_iam_policy(requested_policy_version=3)
            
            for binding in policy.bindings:
                if "allUsers" in binding["members"] or "allAuthenticatedUsers" in binding["members"]:
                    public_buckets.append({
                        "name": bucket.name,
                        "url": f"gs://{bucket.name}",
                        "roles": binding["role"],
                        "members": list(binding["members"]),
                    })
                    break  # Move to the next bucket once a public binding is found

        logger.info(f"Found {len(public_buckets)} public GCS buckets")

        return APIResponse.success(
            data={
                "public_buckets": public_buckets,
                "summary": f"Found {len(public_buckets)} publicly accessible buckets."
            },
            message=f"Analyzed GCS buckets in project {project_id}"
        )

    # ========================================================================
    # NETWORK & DATA-SECURITY METHODS (M2)
    # ========================================================================

    @handle_gcp_errors
    @retry_on_failure()
    def list_subnetworks_flow_log_status(self, project_id: str) -> APIResponse:
        """Enumerate subnets in the project and report which have VPC flow logs disabled."""
        logger.info(f"Listing subnetwork flow log status for project: {project_id}")
        client = self._get_client("compute_subnetworks")
        subnets, disabled = [], []
        for region, response in client.aggregated_list(project=project_id):
            for s in (response.subnetworks or []):
                row = {
                    "name": s.name,
                    "region": region.replace("regions/", ""),
                    "network": s.network.split("/")[-1] if s.network else None,
                    "enable_flow_logs": bool(getattr(s, "enable_flow_logs", False)),
                    "flow_sampling": getattr(s.log_config, "flow_sampling", None) if getattr(s, "log_config", None) else None,
                    "aggregation_interval": (
                        getattr(s.log_config, "aggregation_interval", None).name
                        if getattr(s, "log_config", None) and getattr(s.log_config, "aggregation_interval", None)
                        else None
                    ),
                }
                subnets.append(row)
                if not row["enable_flow_logs"]:
                    disabled.append(row)
        summary = f"{len(disabled)} of {len(subnets)} subnets have VPC flow logs disabled."
        return APIResponse.success(
            data={"subnets": subnets, "disabled": disabled, "summary": summary},
            message=summary,
        )

    @handle_gcp_errors
    @retry_on_failure()
    def get_default_network(self, project_id: str) -> APIResponse:
        """Detect whether the project still has the default VPC network."""
        logger.info(f"Checking default network presence for project: {project_id}")
        client = self._get_client("compute_networks")
        try:
            net = client.get(project=project_id, network="default")
        except gcp_exceptions.NotFound:
            return APIResponse.success(
                data={"present": False, "auto_create_subnetworks": False, "subnetwork_count": 0},
                message="Default VPC absent (good).",
            )
        return APIResponse.success(
            data={
                "present": True,
                "auto_create_subnetworks": bool(getattr(net, "auto_create_subnetworks", False)),
                "subnetwork_count": len(list(net.subnetworks or [])),
            },
            message="Default VPC is present in the project.",
        )

    @handle_gcp_errors
    @retry_on_failure()
    def list_kms_key_rotation_issues(
        self, project_id: str, max_rotation_days: int = 90
    ) -> APIResponse:
        """Find KMS keys without a rotation period or with rotation > max_rotation_days."""
        logger.info(
            f"Checking KMS key rotation for project: {project_id} (max {max_rotation_days}d)"
        )
        client = self._get_client("kms")
        keys, non_compliant = [], []
        rings = client.list_key_rings(parent=f"projects/{project_id}/locations/-")
        for ring in rings:
            for k in client.list_crypto_keys(parent=ring.name):
                rotation_days: Optional[float] = None
                if getattr(k, "rotation_period", None):
                    rotation_days = k.rotation_period.total_seconds() / 86400.0
                next_rotation = (
                    k.next_rotation_time.isoformat() if getattr(k, "next_rotation_time", None) else None
                )
                compliant = (
                    rotation_days is not None and rotation_days <= max_rotation_days
                )
                reason = (
                    None
                    if compliant
                    else (
                        "no rotation period set"
                        if rotation_days is None
                        else f"rotation period {rotation_days:.0f} days exceeds {max_rotation_days}-day threshold"
                    )
                )
                row = {
                    "name": k.name.split("/")[-1],
                    "key_ring": ring.name.split("/")[-1],
                    "location": ring.name.split("/")[-3],
                    "purpose": k.purpose.name if hasattr(k.purpose, "name") else str(k.purpose),
                    "rotation_period_days": rotation_days,
                    "next_rotation_time": next_rotation,
                    "compliant": compliant,
                    "reason": reason,
                }
                keys.append(row)
                if not compliant:
                    non_compliant.append(row)
        return APIResponse.success(
            data={"keys": keys, "non_compliant": non_compliant, "max_rotation_days": max_rotation_days},
            message=f"{len(non_compliant)} of {len(keys)} KMS keys are out of rotation policy.",
        )

    @handle_gcp_errors
    @retry_on_failure()
    def list_secret_manager_secrets(
        self, project_id: str, max_age_days: int = 90
    ) -> APIResponse:
        """List Secret Manager secrets, flagging stale ones and any with public bindings."""
        logger.info(
            f"Listing Secret Manager secrets for project: {project_id} (max age {max_age_days}d)"
        )
        client = self._get_client("secret_manager")
        now = datetime.now(timezone.utc)
        secrets, stale, publicly_bound = [], [], []
        parent = f"projects/{project_id}"
        for s in client.list_secrets(request={"parent": parent}):
            create_time = s.create_time
            age_days = (now - create_time).total_seconds() / 86400.0 if create_time else None
            try:
                policy = client.get_iam_policy(request={"resource": s.name})
                bindings = [
                    {"role": b.role, "members": list(b.members)} for b in policy.bindings
                ]
            except gcp_exceptions.PermissionDenied:
                bindings = []
            has_public = any(
                m in ("allUsers", "allAuthenticatedUsers")
                for b in bindings
                for m in b["members"]
            )
            row = {
                "name": s.name.split("/")[-1],
                "create_time": create_time.isoformat() if create_time else None,
                "age_days": age_days,
                "labels": dict(s.labels) if s.labels else {},
                "bindings": bindings,
                "has_public_binding": has_public,
            }
            secrets.append(row)
            if age_days is not None and age_days > max_age_days:
                stale.append(row)
            if has_public:
                publicly_bound.append(row)
        return APIResponse.success(
            data={
                "secrets": secrets,
                "stale": stale,
                "publicly_bound": publicly_bound,
                "max_age_days": max_age_days,
            },
            message=(
                f"{len(secrets)} secrets; {len(stale)} stale (>{max_age_days}d); "
                f"{len(publicly_bound)} publicly bound."
            ),
        )

    @handle_gcp_errors
    @retry_on_failure()
    def list_public_bigquery_datasets(self, project_id: str) -> APIResponse:
        """Find BigQuery datasets exposed to allUsers or allAuthenticatedUsers."""
        logger.info(f"Checking BigQuery dataset visibility for project: {project_id}")
        from google.cloud import bigquery

        bq = bigquery.Client(project=project_id)
        public = []
        total = 0
        for ref in bq.list_datasets(project=project_id):
            total += 1
            ds = bq.get_dataset(ref.reference)
            for entry in (ds.access_entries or []):
                # entity_id holds the special principals when entity_type == "specialGroup"
                # or "iamMember"; we check both.
                principal = entry.entity_id or ""
                if principal in ("allUsers", "allAuthenticatedUsers"):
                    public.append(
                        {
                            "dataset_id": f"{ds.project}:{ds.dataset_id}",
                            "location": ds.location,
                            "exposed_role": str(entry.role),
                            "exposed_principal": principal,
                        }
                    )
        return APIResponse.success(
            data={
                "public_datasets": public,
                "summary": f"{len(public)} of {total} BigQuery datasets are public.",
            },
            message=f"Inspected {total} BigQuery datasets in {project_id}.",
        )

    @handle_gcp_errors
    @retry_on_failure()
    def list_dnssec_status(self, project_id: str) -> APIResponse:
        """Report DNSSEC state for all managed zones in the project."""
        logger.info(f"Listing DNSSEC status for project: {project_id}")
        dns = self._get_client("dns")
        zones, disabled = [], []
        request = dns.managedZones().list(project=project_id)
        while request is not None:
            resp = request.execute()
            for z in resp.get("managedZones", []):
                state = (z.get("dnssecConfig") or {}).get("state", "off")
                row = {
                    "name": z.get("name"),
                    "dns_name": z.get("dnsName"),
                    "visibility": z.get("visibility", "public"),
                    "dnssec_state": state,
                }
                zones.append(row)
                if state != "on":
                    disabled.append(row)
            request = dns.managedZones().list_next(request, resp)
        return APIResponse.success(
            data={"zones": zones, "disabled": disabled},
            message=f"{len(disabled)} of {len(zones)} managed zones have DNSSEC disabled.",
        )

    @handle_gcp_errors
    @retry_on_failure()
    def list_cloud_armor_coverage(self, project_id: str) -> APIResponse:
        """Enumerate Cloud Armor security policies and flag internet-facing backends without one."""
        logger.info(f"Checking Cloud Armor coverage for project: {project_id}")
        sp_client = self._get_client("compute_security_policies")
        bs_client = self._get_client("compute_backend_services")

        policies = [
            {
                "name": p.name,
                "description": p.description,
                "rule_count": len(list(p.rules or [])),
            }
            for p in sp_client.list(project=project_id)
        ]

        backends, unprotected = [], []
        for region_scope, response in bs_client.aggregated_list(project=project_id):
            for bs in (response.backend_services or []):
                scheme = (
                    bs.load_balancing_scheme.name
                    if hasattr(bs.load_balancing_scheme, "name")
                    else str(bs.load_balancing_scheme)
                )
                has_policy = bool(getattr(bs, "security_policy", None))
                row = {
                    "name": bs.name,
                    "region": region_scope.replace("regions/", "").replace("global", "global"),
                    "load_balancing_scheme": scheme,
                    "has_security_policy": has_policy,
                    "security_policy": bs.security_policy.split("/")[-1] if has_policy else None,
                }
                backends.append(row)
                if scheme in ("EXTERNAL", "EXTERNAL_MANAGED") and not has_policy:
                    unprotected.append(row)
        return APIResponse.success(
            data={
                "policies": policies,
                "backend_services": backends,
                "internet_facing_unprotected": unprotected,
            },
            message=(
                f"{len(policies)} Cloud Armor policies; "
                f"{len(unprotected)} internet-facing backends are unprotected."
            ),
        )
