import os
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest


class TestListPolicyDocuments:
    def test_lists_files(self, tmp_path, monkeypatch):
        monkeypatch.setenv("POLICIES_FOLDER", str(tmp_path))
        (tmp_path / "password-policy.txt").write_text("content")
        (tmp_path / "data-classification.txt").write_text("content")

        from secmind.sub_agents.policy_agent.agent import list_policy_documents
        result = list_policy_documents()
        assert result["status"] == "success"
        assert len(result["files"]) == 2

    def test_empty_dir(self, tmp_path, monkeypatch):
        monkeypatch.setenv("POLICIES_FOLDER", str(tmp_path))

        from secmind.sub_agents.policy_agent.agent import list_policy_documents
        result = list_policy_documents()
        assert result["status"] == "success"
        assert result["files"] == []


class TestReadPolicyFile:
    def test_read_txt(self, tmp_path, monkeypatch):
        monkeypatch.setenv("POLICIES_FOLDER", str(tmp_path))
        (tmp_path / "policy.txt").write_text("Rotate passwords every 90 days.")

        from secmind.sub_agents.policy_agent.agent import read_policy_file
        result = read_policy_file("policy.txt")
        assert result["status"] == "success"
        assert "90 days" in result["content"]

    def test_file_not_found(self, tmp_path, monkeypatch):
        monkeypatch.setenv("POLICIES_FOLDER", str(tmp_path))

        from secmind.sub_agents.policy_agent.agent import read_policy_file
        result = read_policy_file("nonexistent.txt")
        assert result["status"] == "error"

    def test_path_traversal_blocked(self, tmp_path, monkeypatch):
        monkeypatch.setenv("POLICIES_FOLDER", str(tmp_path))

        from secmind.sub_agents.policy_agent.agent import read_policy_file
        result = read_policy_file("../etc/passwd")
        assert result["status"] == "error"

    def test_unsupported_format(self, tmp_path, monkeypatch):
        monkeypatch.setenv("POLICIES_FOLDER", str(tmp_path))
        (tmp_path / "data.csv").write_text("a,b,c")

        from secmind.sub_agents.policy_agent.agent import read_policy_file
        result = read_policy_file("data.csv")
        assert result["status"] == "error"
        assert "Unsupported" in result["error_message"]


class TestSearchPolicyDocuments:
    @patch("secmind.sub_agents.policy_agent.agent.sources")
    def test_search_success(self, mock_sources):
        mock_hit = MagicMock()
        mock_hit.to_dict.return_value = {
            "source": "confluence",
            "title": "Password Policy",
            "snippet": "Rotate every 90 days",
        }
        mock_sources.search_all_sources.return_value = [mock_hit]

        from secmind.sub_agents.policy_agent.agent import search_policy_documents
        result = search_policy_documents("password rotation")
        assert result["status"] == "success"
        assert result["count"] == 1

    @patch("secmind.sub_agents.policy_agent.agent.sources")
    def test_search_error(self, mock_sources):
        mock_sources.search_all_sources.side_effect = Exception("Connection failed")

        from secmind.sub_agents.policy_agent.agent import search_policy_documents
        result = search_policy_documents("anything")
        assert result["status"] == "error"
