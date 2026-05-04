"""
Per-user MemoryManager factory + transparent proxy.

Each user gets their own ``memory/users/<id>/`` directory containing both the
SQLite cache and the ChromaDB vector store. Schema, keys, and method signatures
on :class:`MemoryManager` are unchanged — isolation comes entirely from the
file path. ``MemoryManager`` instances are cached per user so we don't pay the
ChromaDB client / SQLite open cost on every tool call.

When there is no user in context (``adk web``, ``python run_agent.py``,
unit tests), we fall back to the legacy single-tenant ``memory/`` directory
so existing dev data stays accessible.

Most call-sites should just use :class:`MemoryProxy` — every attribute access
is forwarded to the current user's manager, so a sub-agent constructed at
import time still picks up the correct per-user store at tool-call time.
"""
from __future__ import annotations

import logging
from pathlib import Path
from threading import RLock
from typing import Optional

from .memory_manager import MemoryManager
from .user_context import current_user_id

logger = logging.getLogger(__name__)

LEGACY_PATH = "memory"
USERS_BASE = Path("memory/users")

_managers: dict[str, MemoryManager] = {}
_lock = RLock()


def _path_for(user_id: Optional[int]) -> str:
    if user_id is None:
        return LEGACY_PATH
    if not isinstance(user_id, int) or user_id <= 0:
        raise ValueError("user_id must be a positive integer")
    return str(USERS_BASE / str(user_id))


def get_memory_manager(user_id: Optional[int] = None) -> MemoryManager:
    """Return the cached :class:`MemoryManager` for ``user_id``.

    If ``user_id`` is None, falls back to :func:`current_user_id`. If still
    None (no request in flight), returns the legacy single-tenant manager
    rooted at ``memory/``.
    """
    if user_id is None:
        user_id = current_user_id()
    path = _path_for(user_id)
    cached = _managers.get(path)
    if cached is not None:
        return cached
    with _lock:
        cached = _managers.get(path)
        if cached is not None:
            return cached
        mgr = MemoryManager(db_path=path)
        _managers[path] = mgr
        if user_id is None:
            logger.debug("MemoryManager created at legacy path %s (no user in context)", path)
        else:
            logger.info("MemoryManager created for user_id=%s at %s", user_id, path)
        return mgr


class MemoryProxy:
    """Transparent forwarder to the current user's :class:`MemoryManager`.

    Use this in place of ``MemoryManager()`` whenever the instance might
    outlive a single request — every attribute access resolves to the
    correct per-user manager via :func:`current_user_id`.
    """

    __slots__ = ()

    def __getattr__(self, name: str):
        return getattr(get_memory_manager(), name)

    def __repr__(self) -> str:
        uid = current_user_id()
        return f"<MemoryProxy user_id={uid}>"
