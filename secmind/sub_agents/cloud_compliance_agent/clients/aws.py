"""
AWS API Client.
"""

from .base import BaseClient
from ..models import APIResponse

class AWSClient(BaseClient):
    """
    Client for interacting with AWS APIs.
    """

    def list_resources(self, scope: str, asset_types: list[str] | None = None, page_size: int = 100) -> APIResponse:
        return APIResponse.success(data=[], message="Not implemented yet")

    def list_security_sources(self, parent: str) -> APIResponse:
        return APIResponse.success(data=[], message="Not implemented yet")

    def list_findings(self, parent: str, source_id: str | None = None, page_size: int = 100) -> APIResponse:
        return APIResponse.success(data=[], message="Not implemented yet")

    def list_iam_recommendations(self, project_id: str, recommender_id: str | None = None) -> APIResponse:
        return APIResponse.success(data=[], message="Not implemented yet")

    def list_org_policies(self, parent: str) -> APIResponse:
        return APIResponse.success(data=[], message="Not implemented yet")

    def list_service_account_keys(self, project_id: str, max_age_days: int = 90) -> APIResponse:
        return APIResponse.success(data=[], message="Not implemented yet")
