"""Read-through MemoryManager cache for endpoint_security_agent tools.

One generic table (``endpoint_security_cache``); the cache key is a sha256 over
``(provider, integration_name, tool_name, kwargs)`` so swapping integrations
naturally invalidates and the same tool with different filters does not collide.
TTL is applied at read time inside ``MemoryManager.get_endpoint_cache``.

Errors bypass the cache so transient failures don't get pinned.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from typing import Callable

from secmind.memory import get_memory_manager
from secmind.memory_manager import MemoryManager

logger = logging.getLogger(__name__)

ENDPOINT_CACHE_TTL_SECONDS = int(os.environ.get("ENDPOINT_CACHE_TTL_SECONDS", "900"))


def _mem() -> MemoryManager:
    return get_memory_manager()


def _make_cache_key(provider: str, integration_name: str, tool_name: str, kwargs: dict) -> str:
    payload = (
        f"{provider}:{integration_name}:{tool_name}:"
        f"{json.dumps(kwargs, sort_keys=True, default=str)}"
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def cached(
    provider: str,
    integration_name: str,
    tool_name: str,
    kwargs: dict,
    fn: Callable[[], dict],
) -> dict:
    """Read-through cache for endpoint-agent tool envelopes.

    Caches only successful envelopes (``status == "success"``).
    """
    key = _make_cache_key(provider, integration_name, tool_name, kwargs)
    hit = _mem().get_endpoint_cache(key, ttl_seconds=ENDPOINT_CACHE_TTL_SECONDS)
    if hit is not None:
        logger.info("endpoint cache hit: %s/%s (%s)", provider, tool_name, integration_name)
        return hit
    result = fn()
    if isinstance(result, dict) and result.get("status") == "success":
        _mem().add_endpoint_cache(key, result)
    return result


def clear_all() -> int:
    return _mem().clear_endpoint_cache()
