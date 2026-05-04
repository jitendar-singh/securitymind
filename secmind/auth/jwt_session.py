"""HS256 JWT issuance + verification for session cookies.

The signing secret is read from ``SECMIND_JWT_SECRET`` env var. If unset, a
fresh 256-bit secret is generated and persisted to ``memory/.jwt_secret`` —
mirroring the Fernet-key bootstrap pattern in ``integration_store.py``. In
production set ``SECMIND_JWT_SECRET`` explicitly so the secret survives a
``memory/`` reset.
"""
from __future__ import annotations

import logging
import os
import secrets
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import jwt

from .user_store import User, get_user_store

logger = logging.getLogger(__name__)

ENV_VAR = "SECMIND_JWT_SECRET"
KEY_PATH = Path("memory/.jwt_secret")
COOKIE_NAME = "secmind_session"
TOKEN_TTL = timedelta(days=7)
ALG = "HS256"


def _load_or_create_secret() -> str:
    env_secret = os.getenv(ENV_VAR)
    if env_secret:
        return env_secret
    if KEY_PATH.exists():
        return KEY_PATH.read_text(encoding="utf-8").strip()

    logger.warning(
        "%s not set and %s missing — generating a new JWT secret. "
        "Set %s in production so sessions survive memory/ resets.",
        ENV_VAR, KEY_PATH, ENV_VAR,
    )
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    secret = secrets.token_urlsafe(48)
    KEY_PATH.write_text(secret, encoding="utf-8")
    try:
        os.chmod(KEY_PATH, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return secret


_secret: Optional[str] = None


def _get_secret() -> str:
    global _secret
    if _secret is None:
        _secret = _load_or_create_secret()
    return _secret


def issue(user: User) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user.id),
        "email": user.email,
        "role": user.role,
        "iat": int(now.timestamp()),
        "exp": int((now + TOKEN_TTL).timestamp()),
    }
    return jwt.encode(payload, _get_secret(), algorithm=ALG)


def verify(token: str) -> Optional[User]:
    if not token:
        return None
    try:
        payload = jwt.decode(token, _get_secret(), algorithms=[ALG])
    except jwt.PyJWTError as exc:
        logger.debug("JWT verify failed: %s", exc)
        return None
    try:
        user_id = int(payload.get("sub", ""))
    except (TypeError, ValueError):
        return None
    return get_user_store().get(user_id)
