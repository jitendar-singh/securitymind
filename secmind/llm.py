"""Shared LLM call helper that respects the user's model selection.

Sub-agents that make direct LLM calls (threat_modeler, code_review_agent) use
this instead of calling ``genai.Client()`` directly, so they honour the model
chosen in Settings — including Claude and GPT models via litellm.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

from google import genai
from google.genai import types as genai_types

logger = logging.getLogger(__name__)

_genai_client: Optional[genai.Client] = None


def _get_genai_client() -> genai.Client:
    global _genai_client
    if _genai_client is None:
        _genai_client = genai.Client()
    return _genai_client


def resolve_model_id(agent_model: Any) -> str:
    """Extract a plain model-id string from an ADK agent's ``.model`` attribute.

    - Plain string (Gemini) → returned as-is.
    - ``LiteLlm`` instance → its ``.model`` attribute (e.g. ``anthropic/claude-...``).
    """
    if isinstance(agent_model, str):
        return agent_model
    model_attr = getattr(agent_model, "model", None)
    if isinstance(model_attr, str):
        return model_attr
    return str(agent_model)


def _extract_litellm_kwargs(agent_model: Any) -> dict:
    """Pull api_key and other kwargs from a LiteLlm instance."""
    extra = getattr(agent_model, "_additional_args", None)
    if isinstance(extra, dict):
        return dict(extra)
    return {}


def generate_json(
    prompt: str,
    agent_model: Any,
    *,
    temperature: float = 0.5,
    response_schema: Any = None,
) -> Optional[str]:
    """Make an LLM call requesting JSON output, returning the raw JSON text.

    Routes to ``genai`` for Gemini models and ``litellm`` for everything else.

    Args:
        prompt: The user/content prompt.
        agent_model: The ADK agent's ``.model`` attribute — a string for Gemini,
            a ``LiteLlm`` instance for Claude/GPT.
        temperature: Sampling temperature.
        response_schema: (Gemini only) A Pydantic model class for structured output.

    Returns:
        The raw JSON text from the model, or None on failure.
    """
    model_id = resolve_model_id(agent_model)

    if model_id.startswith("gemini"):
        return _call_gemini(prompt, model_id, temperature, response_schema)
    return _call_litellm(prompt, model_id, agent_model, temperature)


def _call_gemini(
    prompt: str,
    model_id: str,
    temperature: float,
    response_schema: Any,
) -> Optional[str]:
    config_kwargs: dict[str, Any] = {
        "response_mime_type": "application/json",
        "temperature": temperature,
    }
    if response_schema is not None:
        config_kwargs["response_schema"] = response_schema

    config = genai_types.GenerateContentConfig(**config_kwargs)
    response = _get_genai_client().models.generate_content(
        model=model_id,
        contents=prompt,
        config=config,
    )
    return (response.text or "").strip() or None


def _call_litellm(
    prompt: str,
    model_id: str,
    agent_model: Any,
    temperature: float,
) -> Optional[str]:
    import litellm

    kwargs = _extract_litellm_kwargs(agent_model)
    kwargs["temperature"] = temperature

    response = litellm.completion(
        model=model_id,
        messages=[
            {
                "role": "system",
                "content": "Respond with valid JSON only. No markdown fences, no commentary.",
            },
            {"role": "user", "content": prompt},
        ],
        **kwargs,
    )
    text = response.choices[0].message.content or ""
    text = text.strip()
    if text.startswith("```"):
        text = text.split("```", 2)[1]
        if text.startswith("json"):
            text = text[4:]
        text = text.strip()
    return text or None
