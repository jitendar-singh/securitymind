from unittest.mock import patch, MagicMock

import pytest

from secmind.llm_credentials import lookup_api_key_for_model


class TestLookupApiKeyForModel:
    @patch("secmind.llm_credentials.get_store")
    def test_claude_model_found(self, mock_get_store):
        mock_store = MagicMock()
        mock_store.iter_active.return_value = [
            {"provider": "anthropic", "config": {"ANTHROPIC_API_KEY": "sk-ant-xxx"}},
        ]
        mock_get_store.return_value = mock_store

        key = lookup_api_key_for_model("claude-3-sonnet", user_id=1)
        assert key == "sk-ant-xxx"

    @patch("secmind.llm_credentials.get_store")
    def test_openai_model_found(self, mock_get_store):
        mock_store = MagicMock()
        mock_store.iter_active.return_value = [
            {"provider": "openai", "config": {"OPENAI_API_KEY": "sk-openai-xxx"}},
        ]
        mock_get_store.return_value = mock_store

        key = lookup_api_key_for_model("gpt-4o", user_id=1)
        assert key == "sk-openai-xxx"

    @patch("secmind.llm_credentials.get_store")
    def test_no_matching_integration(self, mock_get_store):
        mock_store = MagicMock()
        mock_store.iter_active.return_value = []
        mock_get_store.return_value = mock_store

        key = lookup_api_key_for_model("claude-3-opus", user_id=1)
        assert key is None

    @patch("secmind.llm_credentials.get_store")
    def test_unknown_model_prefix(self, mock_get_store):
        key = lookup_api_key_for_model("llama-3-70b", user_id=1)
        assert key is None

    @patch("secmind.llm_credentials.get_store")
    def test_gemini_model_returns_none(self, mock_get_store):
        key = lookup_api_key_for_model("gemini-2.5-pro", user_id=1)
        assert key is None

    @patch("secmind.llm_credentials.get_store")
    def test_missing_config_key(self, mock_get_store):
        mock_store = MagicMock()
        mock_store.iter_active.return_value = [
            {"provider": "anthropic", "config": {}},
        ]
        mock_get_store.return_value = mock_store

        key = lookup_api_key_for_model("claude-3-haiku", user_id=1)
        assert key is None
