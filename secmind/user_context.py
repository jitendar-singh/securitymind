"""
Request-scoped current-user context.

Sub-agent tools (e.g. endpoint_security_agent, sources/*) need to know which
user is making the current request so they can pull that user's integrations
from the IntegrationStore. Those callers don't have direct access to Flask's
``g.user``, so we surface it via a ContextVar set/cleared by the /chat handler.

Usage::

    from secmind.user_context import user_scope, current_user_id

    with user_scope(g.user.id):
        run_agent(...)            # tool calls inside see this user

    uid = current_user_id()       # may be None outside a request
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterator, Optional

_current_user_id: ContextVar[Optional[int]] = ContextVar(
    "secmind_current_user_id", default=None
)


def current_user_id() -> Optional[int]:
    """Return the user id bound to this context, or None if unset."""
    return _current_user_id.get()


def require_current_user_id() -> int:
    uid = _current_user_id.get()
    if uid is None:
        raise RuntimeError(
            "No current user in context — wrap the call site in user_scope(...)."
        )
    return uid


@contextmanager
def user_scope(user_id: Optional[int]) -> Iterator[None]:
    """Bind ``user_id`` for the duration of the with-block."""
    token = _current_user_id.set(user_id)
    try:
        yield
    finally:
        _current_user_id.reset(token)
