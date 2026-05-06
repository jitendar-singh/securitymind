"""Flask middleware: ``@require_auth`` decorator + helpers for cookie session."""
from __future__ import annotations

import logging
import os
from functools import wraps
from typing import Callable

from flask import Response, g, jsonify, request

from .jwt_session import COOKIE_NAME, TOKEN_TTL, issue, verify
from .user_store import User

logger = logging.getLogger(__name__)


def require_auth(fn: Callable) -> Callable:
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = request.cookies.get(COOKIE_NAME, "")
        user = verify(token)
        if user is None:
            return jsonify({"error": "unauthenticated"}), 401
        g.user = user
        return fn(*args, **kwargs)

    return wrapper


def set_session_cookie(response: Response, user: User) -> Response:
    """Attach the signed session cookie for ``user`` to ``response``."""
    _default = "0" if os.environ.get("SECMIND_ENV", "development") == "development" else "1"
    secure = os.environ.get("SECMIND_COOKIE_SECURE", _default) == "1"
    response.set_cookie(
        COOKIE_NAME,
        issue(user),
        max_age=int(TOKEN_TTL.total_seconds()),
        httponly=True,
        secure=secure,
        samesite="Lax",
        path="/",
    )
    return response


def clear_session_cookie(response: Response) -> Response:
    response.delete_cookie(COOKIE_NAME, path="/")
    return response
