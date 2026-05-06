from types import SimpleNamespace
from unittest.mock import patch, MagicMock

import pytest

from secmind.llm import resolve_model_id, _extract_litellm_kwargs, generate_json


class TestResolveModelId:
    def test_plain_string(self):
        assert resolve_model_id("gemini-2.5-pro") == "gemini-2.5-pro"

    def test_litellm_instance(self):
        llm = SimpleNamespace(model="anthropic/claude-3-sonnet")
        assert resolve_model_id(llm) == "anthropic/claude-3-sonnet"

    def test_fallback_to_str(self):
        obj = 42
        assert resolve_model_id(obj) == "42"


class TestExtractLitellmKwargs:
    def test_with_additional_args(self):
        llm = SimpleNamespace(_additional_args={"api_key": "sk-xxx", "timeout": 30})
        result = _extract_litellm_kwargs(llm)
        assert result["api_key"] == "sk-xxx"
        assert result["timeout"] == 30

    def test_no_additional_args(self):
        llm = SimpleNamespace()
        assert _extract_litellm_kwargs(llm) == {}

    def test_non_dict_additional_args(self):
        llm = SimpleNamespace(_additional_args="not-a-dict")
        assert _extract_litellm_kwargs(llm) == {}


class TestGenerateJson:
    @patch("secmind.llm._get_genai_client")
    def test_gemini_route(self, mock_get_client):
        mock_response = MagicMock()
        mock_response.text = '{"result": "ok"}'
        mock_get_client.return_value.models.generate_content.return_value = mock_response

        result = generate_json("test prompt", "gemini-2.5-flash")
        assert result == '{"result": "ok"}'
        mock_get_client.return_value.models.generate_content.assert_called_once()

    @patch("secmind.llm._get_genai_client")
    def test_gemini_empty_response(self, mock_get_client):
        mock_response = MagicMock()
        mock_response.text = ""
        mock_get_client.return_value.models.generate_content.return_value = mock_response

        result = generate_json("test prompt", "gemini-2.5-flash")
        assert result is None

    @patch("secmind.llm.litellm", create=True)
    def test_litellm_route(self, mock_litellm):
        mock_choice = MagicMock()
        mock_choice.message.content = '{"answer": 42}'
        mock_response = MagicMock()
        mock_response.choices = [mock_choice]

        import secmind.llm
        with patch.object(secmind.llm, "_call_litellm", return_value='{"answer": 42}'):
            result = generate_json("test", SimpleNamespace(model="anthropic/claude-3"))
            assert result == '{"answer": 42}'

    @patch("secmind.llm._get_genai_client")
    def test_gemini_with_schema(self, mock_get_client):
        mock_response = MagicMock()
        mock_response.text = '{"issues": []}'
        mock_get_client.return_value.models.generate_content.return_value = mock_response

        from pydantic import BaseModel
        class TestSchema(BaseModel):
            issues: list

        result = generate_json("review code", "gemini-2.5-pro", response_schema=TestSchema)
        assert result == '{"issues": []}'

    @patch("secmind.llm._get_genai_client")
    def test_gemini_exception_propagates(self, mock_get_client):
        mock_get_client.return_value.models.generate_content.side_effect = Exception("API down")
        with pytest.raises(Exception, match="API down"):
            generate_json("test", "gemini-2.5-flash")
