"""
Resolve a user's LLM provider API key from their active integrations.

LiteLlm normally reads ``ANTHROPIC_API_KEY`` / ``OPENAI_API_KEY`` from
``os.environ``. Under multi-tenant load that's racy — two concurrent /chat
requests from different users would clobber each other via the env shim.
This helper lets the caller pass the api_key explicitly into ``LiteLlm(...)``
so the LLM path never depends on process-global env state.
"""
from __future__ import annotations

from typing import Optional

from .integration_store import get_store

# Map a model-id prefix to ``(integration provider id, config field name)``.
# Order matters: more specific prefixes ('gpt-') before broader ones ('o').
_PROVIDER_FOR_PREFIX: tuple[tuple[str, str, str], ...] = (
    ("claude", "anthropic", "ANTHROPIC_API_KEY"),
    ("gpt-",   "openai",    "OPENAI_API_KEY"),
    ("o",      "openai",    "OPENAI_API_KEY"),
)


def lookup_api_key_for_model(model_id: str, user_id: int) -> Optional[str]:
    """Return the API key the user has configured for ``model_id``'s provider,
    or None if no active matching integration is set."""
    for prefix, provider, key_name in _PROVIDER_FOR_PREFIX:
        if model_id.startswith(prefix):
            for rec in get_store().iter_active(user_id):
                if rec["provider"] != provider:
                    continue
                api_key = (rec.get("config") or {}).get(key_name)
                if api_key:
                    return str(api_key)
            return None
    return None
