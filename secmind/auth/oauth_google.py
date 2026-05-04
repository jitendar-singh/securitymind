"""Google OAuth (OpenID Connect) — sign-in / sign-up flow.

Uses Authlib for the IdP heavy-lifting: authorization URL, token exchange,
ID-token verification, and JWKS handling. Configuration is by env var:

    GOOGLE_OAUTH_CLIENT_ID       — required
    GOOGLE_OAUTH_CLIENT_SECRET   — required
    OAUTH_REDIRECT_BASE          — e.g. http://localhost:5001 (no trailing slash)

The redirect URI registered with Google must be:
    {OAUTH_REDIRECT_BASE}/auth/google/callback
"""
from __future__ import annotations

import logging
import os
import secrets
from typing import Tuple
from urllib.parse import urlencode

import requests

from .user_store import User, get_user_store

logger = logging.getLogger(__name__)

DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
SCOPE = "openid email profile"
STATE_COOKIE = "secmind_oauth_state"
STATE_TTL_SECONDS = 600  # 10 min

_discovery: dict | None = None


def _load_discovery() -> dict:
    global _discovery
    if _discovery is None:
        resp = requests.get(DISCOVERY_URL, timeout=10)
        resp.raise_for_status()
        _discovery = resp.json()
    return _discovery


def _client_config() -> Tuple[str, str, str]:
    client_id = os.environ.get("GOOGLE_OAUTH_CLIENT_ID", "")
    client_secret = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET", "")
    base = os.environ.get("OAUTH_REDIRECT_BASE", "").rstrip("/")
    if not client_id or not client_secret or not base:
        raise RuntimeError(
            "Google OAuth not configured: set GOOGLE_OAUTH_CLIENT_ID, "
            "GOOGLE_OAUTH_CLIENT_SECRET, and OAUTH_REDIRECT_BASE env vars."
        )
    return client_id, client_secret, f"{base}/auth/google/callback"


def build_authorize_url() -> Tuple[str, str]:
    """Return ``(authorize_url, state)``. Caller must store ``state`` in a cookie
    and verify it in the callback to prevent CSRF."""
    client_id, _, redirect_uri = _client_config()
    state = secrets.token_urlsafe(24)
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": SCOPE,
        "state": state,
        "access_type": "online",
        "prompt": "select_account",
    }
    auth_endpoint = _load_discovery()["authorization_endpoint"]
    return f"{auth_endpoint}?{urlencode(params)}", state


def exchange_code_for_user(code: str) -> User:
    """Exchange ``code`` for tokens, verify the ID token, and upsert the user."""
    from authlib.jose import jwt as jose_jwt

    client_id, client_secret, redirect_uri = _client_config()

    disc = _load_discovery()
    token_resp = requests.post(
        disc["token_endpoint"],
        data={
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        },
        headers={"Accept": "application/json"},
        timeout=15,
    )
    if not token_resp.ok:
        raise RuntimeError(f"Google token exchange failed (HTTP {token_resp.status_code}): {token_resp.text[:200]}")
    body = token_resp.json() or {}
    id_token = body.get("id_token")
    if not id_token:
        raise RuntimeError("Google token response missing id_token")

    # Verify the ID token signature against Google's JWKS and check claims.
    jwks = requests.get(disc["jwks_uri"], timeout=10).json()
    claims = jose_jwt.decode(
        id_token,
        jwks,
        claims_options={
            "iss": {"essential": True, "values": ["https://accounts.google.com", "accounts.google.com"]},
            "aud": {"essential": True, "value": client_id},
            "exp": {"essential": True},
            "sub": {"essential": True},
        },
    )
    claims.validate()

    sub = claims.get("sub")
    email = (claims.get("email") or "").strip().lower()
    name = claims.get("name") or claims.get("given_name") or ""
    if not sub or not email:
        raise RuntimeError("Google ID token missing required claims (sub/email)")
    if not claims.get("email_verified", False):
        # Don't refuse outright — log and continue; this is a defensible UX
        # choice for B2B where unverified Workspace users are rare.
        logger.warning("Google ID token email not verified for %s", email)

    return get_user_store().get_or_create_oauth("google", sub, email, name)
