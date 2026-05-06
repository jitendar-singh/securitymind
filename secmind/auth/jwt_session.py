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
import sqlite3
import stat
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import jwt

from .user_store import User, get_user_store

logger = logging.getLogger(__name__)

ENV_VAR = "SECMIND_JWT_SECRET"
KEY_PATH = Path("memory/.jwt_secret")
COOKIE_NAME = "secmind_session"
TOKEN_TTL = timedelta(hours=2)
ALG = "HS256"

REVOCATION_DB = Path("memory/revoked_tokens.db")


def _load_or_create_secret() -> str:
    env_secret = os.getenv(ENV_VAR)
    if env_secret:
        return env_secret
    if KEY_PATH.exists():
        return KEY_PATH.read_text(encoding="utf-8").strip()

    if os.getenv("SECMIND_ENV", "development") != "development":
        raise RuntimeError(
            f"{ENV_VAR} is not set. "
            f"In production, set this env var to a secret string "
            f"(generate one with: python -c 'import secrets; print(secrets.token_urlsafe(48))')."
        )

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


class _RevocationStore:
    """SQLite-backed set of revoked JWT IDs (jti claims)."""

    def __init__(self) -> None:
        REVOCATION_DB.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(REVOCATION_DB), check_same_thread=False)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS revoked_tokens (
                jti TEXT PRIMARY KEY,
                revoked_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def revoke(self, jti: str, expires_at: datetime) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            "INSERT OR IGNORE INTO revoked_tokens (jti, revoked_at, expires_at) VALUES (?, ?, ?)",
            (jti, now, expires_at.isoformat()),
        )
        self._conn.commit()

    def is_revoked(self, jti: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM revoked_tokens WHERE jti = ?", (jti,)
        ).fetchone()
        return row is not None

    def purge_expired(self) -> int:
        now = datetime.now(timezone.utc).isoformat()
        cursor = self._conn.execute(
            "DELETE FROM revoked_tokens WHERE expires_at < ?", (now,)
        )
        self._conn.commit()
        return cursor.rowcount


_revocation_store: Optional[_RevocationStore] = None


def _get_revocation_store() -> _RevocationStore:
    global _revocation_store
    if _revocation_store is None:
        _revocation_store = _RevocationStore()
    return _revocation_store


def issue(user: User) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user.id),
        "email": user.email,
        "role": user.role,
        "jti": uuid.uuid4().hex,
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

    jti = payload.get("jti")
    if jti and _get_revocation_store().is_revoked(jti):
        logger.debug("JWT jti=%s has been revoked", jti)
        return None

    try:
        user_id = int(payload.get("sub", ""))
    except (TypeError, ValueError):
        return None
    return get_user_store().get(user_id)


def revoke(token: str) -> bool:
    """Add a token to the revocation list. Returns True if successfully revoked."""
    if not token:
        return False
    try:
        payload = jwt.decode(token, _get_secret(), algorithms=[ALG])
    except jwt.PyJWTError:
        return False
    jti = payload.get("jti")
    if not jti:
        return False
    exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
    _get_revocation_store().revoke(jti, exp)
    return True
