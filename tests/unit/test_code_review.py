import json
from unittest.mock import patch, MagicMock

import pytest


class TestReviewCode:
    @patch("secmind.sub_agents.code_review_agent.agent.get_memory_manager")
    @patch("secmind.sub_agents.code_review_agent.agent.generate_json")
    def test_successful_review(self, mock_gen, mock_get_mm):
        mock_mm = MagicMock()
        mock_mm.get_code_review.return_value = None
        mock_get_mm.return_value = mock_mm

        review_data = {
            "issues": [{"type": "Bug", "description": "Division by zero", "location": "line 3"}],
            "fixes": ["Add zero check"],
            "overall_comments": "Minor issue found",
        }
        mock_gen.return_value = json.dumps(review_data)

        from secmind.sub_agents.code_review_agent.agent import review_code
        result = review_code("def foo(x): return 1/x")

        assert result["issues"][0]["type"] == "Bug"
        assert len(result["fixes"]) == 1
        mock_mm.add_code_review.assert_called_once()

    @patch("secmind.sub_agents.code_review_agent.agent.get_memory_manager")
    def test_cache_hit(self, mock_get_mm):
        cached = {
            "issues": [],
            "fixes": [],
            "overall_comments": "All good",
        }
        mock_mm = MagicMock()
        mock_mm.get_code_review.return_value = cached
        mock_get_mm.return_value = mock_mm

        from secmind.sub_agents.code_review_agent.agent import review_code
        result = review_code("def bar(): pass")
        assert result["overall_comments"] == "All good"

    @patch("secmind.sub_agents.code_review_agent.agent.get_memory_manager")
    @patch("secmind.sub_agents.code_review_agent.agent.generate_json")
    def test_llm_error_returns_error_issue(self, mock_gen, mock_get_mm):
        mock_mm = MagicMock()
        mock_mm.get_code_review.return_value = None
        mock_get_mm.return_value = mock_mm
        mock_gen.side_effect = Exception("LLM unavailable")

        from secmind.sub_agents.code_review_agent.agent import review_code
        result = review_code("def baz(): pass")
        assert result["issues"][0]["type"] == "Error"
        assert "Failed" in result["issues"][0]["description"]


class TestGetGithubPrDiff:
    @patch("secmind.sub_agents.code_review_agent.agent.requests")
    def test_valid_pr_url(self, mock_requests):
        mock_resp = MagicMock()
        mock_resp.text = "diff --git a/file.py b/file.py\n+new line"
        mock_resp.raise_for_status.return_value = None
        mock_requests.get.return_value = mock_resp

        from secmind.sub_agents.code_review_agent.agent import get_github_pr_diff
        result = get_github_pr_diff("https://github.com/org/repo/pull/1")
        assert "diff" in result
        mock_requests.get.assert_called_once_with("https://github.com/org/repo/pull/1.diff")

    def test_invalid_url(self):
        from secmind.sub_agents.code_review_agent.agent import get_github_pr_diff
        result = get_github_pr_diff("https://gitlab.com/org/repo/-/merge_requests/1")
        assert "Invalid" in result

    @patch("secmind.sub_agents.code_review_agent.agent.requests")
    def test_http_error(self, mock_requests):
        mock_requests.get.side_effect = Exception("404 Not Found")

        from secmind.sub_agents.code_review_agent.agent import get_github_pr_diff
        result = get_github_pr_diff("https://github.com/org/repo/pull/9999")
        assert "Error" in result
