"""
Project a user's active integrations' decrypted config into ``os.environ``.

Existing sub-agents read credentials directly from env vars (GOOGLE_API_KEY,
NVD_API_KEY, JIRA_*, AWS_*, etc.). This shim lets users supply those values via
the IntegrationStore UI without changing sub-agent code.

With per-user IntegrationStore scoping, the shim is no longer applied at
startup — there is no single "active" set globally. Instead, the /chat
handler wraps each request in :func:`apply_integrations_for_request`, which
sets the user's vars and restores the previous values on exit.

Note: ``os.environ`` is process-global. If two users send concurrent /chat
requests in a threaded Flask deployment, their env mutations can race.
This is a known limitation inherited from the pre-multitenant design — a
proper fix means passing credentials directly to clients, which is out of
scope for the per-user-scoping refactor.
"""
from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from typing import Iterator

from .integration_store import IntegrationStore, get_store

logger = logging.getLogger(__name__)

# Sentinel used to remember "this var was unset before we set it" so we can
# delete it on exit instead of restoring an empty string.
_UNSET = object()


@contextmanager
def apply_integrations_for_request(
    user_id: int,
    *,
    store: IntegrationStore | None = None,
    overwrite: bool = True,
) -> Iterator[list[str]]:
    """Project the user's active integrations into env for the with-block.

    By default, integration values *win* over any pre-existing env values
    inside the block (``overwrite=True``). On exit, every var we touched is
    restored to its original value (or unset if it didn't exist before).

    Yields the list of env var names that were written so callers can log /
    introspect.
    """
    s = store or get_store()
    try:
        records = list(s.iter_active(user_id))
    except Exception:
        logger.exception(
            "Failed to load integrations for env shim (user_id=%s) — skipping",
            user_id,
        )
        records = []

    backup: dict[str, object] = {}
    applied: list[str] = []

    try:
        for rec in records:
            for key, value in (rec.get("config") or {}).items():
                if not isinstance(key, str) or not key:
                    continue
                if not overwrite and key in os.environ:
                    continue
                if key not in backup:
                    backup[key] = os.environ.get(key, _UNSET)
                os.environ[key] = "" if value is None else str(value)
                applied.append(key)

        if applied:
            logger.info(
                "Projected %d env var(s) from %d active integration(s) for user_id=%s",
                len(applied),
                len(records),
                user_id,
            )

        yield applied
    finally:
        for key, prev in backup.items():
            if prev is _UNSET:
                os.environ.pop(key, None)
            else:
                os.environ[key] = prev  # type: ignore[assignment]
