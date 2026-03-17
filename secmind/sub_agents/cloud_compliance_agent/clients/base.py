"""
Base client for all cloud providers.
"""

from abc import ABC, abstractmethod
from ..models import APIResponse

class BaseClient(ABC):
    """
    Abstract base class for all cloud provider clients.
    """

    @abstractmethod
    def list_resources(self, scope: str, asset_types: list[str] | None = None, page_size: int = 100) -> APIResponse:
        """
        List cloud resources.
        """
        pass

    @abstractmethod
    def list_security_sources(self, parent: str) -> APIResponse:
        """
        List security sources.
        """
        pass

    @abstractmethod
    def list_findings(self, parent: str, source_id: str | None = None, page_size: int = 100) -> APIResponse:
        """
        List security findings.
        """
        pass

    @abstractmethod
    def list_iam_recommendations(self, project_id: str, recommender_id: str) -> APIResponse:
        """
        List IAM recommendations.
        """
        pass

    @abstractmethod
    def list_org_policies(self, parent: str) -> APIResponse:
        """
        List organization policies.
        """
        pass

    @abstractmethod
    def list_service_account_keys(self, project_id: str, max_age_days: int = 90) -> APIResponse:
        """
        List and check service account keys.
        """
        pass
