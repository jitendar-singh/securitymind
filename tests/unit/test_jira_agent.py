from unittest.mock import patch, MagicMock

import pytest


class TestCreateJiraIssue:
    @patch("secmind.sub_agents.jira_agent.agent.jira")
    def test_successful_create(self, mock_jira):
        mock_jira.create_issue.return_value = {"key": "SEC-123"}

        from secmind.sub_agents.jira_agent.agent import create_jira_issue
        result = create_jira_issue(
            project_key="SEC",
            summary="Critical vuln found",
            description="CVE-2024-1234 in prod",
            issue_type="Bug",
        )
        assert result["status"] == "success"
        assert result["issue_key"] == "SEC-123"
        mock_jira.create_issue.assert_called_once()

    @patch("secmind.sub_agents.jira_agent.agent.jira")
    def test_jira_api_error(self, mock_jira):
        mock_jira.create_issue.side_effect = Exception("Jira API error: 401 Unauthorized")

        from secmind.sub_agents.jira_agent.agent import create_jira_issue
        result = create_jira_issue(
            project_key="SEC",
            summary="Test",
            description="Test desc",
        )
        assert result["status"] == "error"
        assert "401" in result["error_message"]

    @patch("secmind.sub_agents.jira_agent.agent.jira")
    def test_default_issue_type(self, mock_jira):
        mock_jira.create_issue.return_value = {"key": "SEC-456"}

        from secmind.sub_agents.jira_agent.agent import create_jira_issue
        result = create_jira_issue("SEC", "Summary", "Description")

        call_args = mock_jira.create_issue.call_args
        fields = call_args[1]["fields"] if "fields" in call_args[1] else call_args[0][0]
        assert fields["issuetype"]["name"] == "Bug"
