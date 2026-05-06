"""User-scoped reports directory helper."""

import os

from secmind.user_context import current_user_id

_BASE = os.path.abspath(os.environ.get("REPORTS_DIR", "reports"))


def user_reports_dir() -> str:
    """Return the reports directory for the current user.

    When a user is in context, returns ``<base>/user_<id>/`` and creates it
    if necessary.  Falls back to the flat base directory for CLI / adk-web
    invocations where no user context is set.
    """
    uid = current_user_id()
    if uid is None:
        os.makedirs(_BASE, exist_ok=True)
        return _BASE
    d = os.path.join(_BASE, f"user_{uid}")
    os.makedirs(d, exist_ok=True)
    return d
