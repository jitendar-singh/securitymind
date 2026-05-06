from unittest.mock import patch, MagicMock
from types import SimpleNamespace

import pytest

from secmind.sub_agents.cloud_compliance_agent.agent import (
    validate_project_id,
    validate_organization_id,
    _validate_cloud,
    _validate_scope,
)


class TestValidation:
    def test_valid_project_id(self):
        assert validate_project_id("my-project-123") is True

    def test_invalid_project_id_uppercase(self):
        assert validate_project_id("My-Project") is False

    def test_invalid_project_id_too_short(self):
        assert validate_project_id("ab") is False

    def test_valid_organization_id(self):
        assert validate_organization_id("123456789") is True

    def test_invalid_organization_id(self):
        assert validate_organization_id("abc") is False

    def test_validate_cloud_gcp(self):
        assert _validate_cloud("gcp") is None

    def test_validate_cloud_invalid(self):
        err = _validate_cloud("invalid")
        assert err["status"] == "error"
        assert "Unsupported" in err["message"]

    def test_validate_scope_valid_project(self):
        assert _validate_scope("projects/my-project-123") is None

    def test_validate_scope_valid_org(self):
        assert _validate_scope("organizations/123456789") is None

    def test_validate_scope_invalid_prefix(self):
        err = _validate_scope("folders/12345")
        assert err["status"] == "error"

    def test_validate_scope_invalid_project_id(self):
        err = _validate_scope("projects/INVALID")
        assert err["status"] == "error"


class TestListResources:
    @patch("secmind.sub_agents.cloud_compliance_agent.agent._get_client")
    @patch("secmind.sub_agents.cloud_compliance_agent.agent.get_memory_manager")
    def test_success(self, mock_get_mm, mock_get_client):
        mock_mm = MagicMock()
        mock_mm.get_cloud_resources.return_value = None
        mock_get_mm.return_value = mock_mm

        mock_response = MagicMock()
        mock_response.status = "success"
        mock_response.to_dict.return_value = {
            "status": "success",
            "data": [{"type": "compute", "name": "vm-1"}],
            "message": "Found 1 resource",
        }
        mock_client = MagicMock()
        mock_client.list_resources.return_value = mock_response
        mock_get_client.return_value = mock_client

        from secmind.sub_agents.cloud_compliance_agent.agent import list_resources
        result = list_resources("gcp", "projects/my-project-123")
        assert result["status"] == "success"
        mock_mm.add_cloud_resources.assert_called_once()

    @patch("secmind.sub_agents.cloud_compliance_agent.agent.get_memory_manager")
    def test_invalid_cloud(self, mock_get_mm):
        from secmind.sub_agents.cloud_compliance_agent.agent import list_resources
        result = list_resources("invalid", "projects/my-project-123")
        assert result["status"] == "error"

    @patch("secmind.sub_agents.cloud_compliance_agent.agent._get_client")
    @patch("secmind.sub_agents.cloud_compliance_agent.agent.get_memory_manager")
    def test_cache_hit(self, mock_get_mm, mock_get_client):
        cached = {"status": "success", "data": [{"cached": True}]}
        mock_mm = MagicMock()
        mock_mm.get_cloud_resources.return_value = cached
        mock_get_mm.return_value = mock_mm

        from secmind.sub_agents.cloud_compliance_agent.agent import list_resources
        result = list_resources("gcp", "projects/my-project-123")
        assert result == cached
        mock_get_client.assert_not_called()


class TestCheckSecurityPosture:
    @patch("secmind.sub_agents.cloud_compliance_agent.agent._get_client")
    @patch("secmind.sub_agents.cloud_compliance_agent.agent.get_memory_manager")
    def test_success(self, mock_get_mm, mock_get_client):
        mock_mm = MagicMock()
        mock_mm.get_security_posture.return_value = None
        mock_get_mm.return_value = mock_mm

        mock_response = MagicMock()
        mock_response.status = "success"
        mock_response.to_dict.return_value = {
            "status": "success",
            "data": {"findings": 5},
        }
        mock_client = MagicMock()
        mock_client.list_findings.return_value = mock_response
        mock_get_client.return_value = mock_client

        from secmind.sub_agents.cloud_compliance_agent.agent import check_security_posture
        result = check_security_posture("gcp", "projects/my-project-123")
        assert result["status"] == "success"


class TestCheckIamRecommendations:
    @patch("secmind.sub_agents.cloud_compliance_agent.agent._get_client")
    @patch("secmind.sub_agents.cloud_compliance_agent.agent.get_memory_manager")
    def test_success(self, mock_get_mm, mock_get_client):
        mock_mm = MagicMock()
        mock_mm.get_iam_recommendations.return_value = None
        mock_get_mm.return_value = mock_mm

        mock_response = MagicMock()
        mock_response.status = "success"
        mock_response.to_dict.return_value = {
            "status": "success",
            "data": {"recommendations": []},
        }
        mock_client = MagicMock()
        mock_client.list_iam_recommendations.return_value = mock_response
        mock_get_client.return_value = mock_client

        from secmind.sub_agents.cloud_compliance_agent.agent import check_iam_recommendations
        result = check_iam_recommendations("gcp", "my-project-123")
        assert result["status"] == "success"
