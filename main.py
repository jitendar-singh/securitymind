import asyncio
import logging
import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from flask import Flask, abort, g, jsonify, redirect, request, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from google.adk.runners import Runner
from google.adk.sessions import DatabaseSessionService
from google.genai import types

from google.adk.models.lite_llm import LiteLlm

from secmind.agent import AgentConfig, secmind
from secmind.auth import require_auth
from secmind.auth.jwt_session import COOKIE_NAME as SESSION_COOKIE_NAME, revoke as revoke_token
from secmind.auth.middleware import (
    clear_session_cookie,
    set_session_cookie,
)
from secmind.auth.oauth_google import (
    STATE_COOKIE,
    STATE_TTL_SECONDS,
    build_authorize_url,
    exchange_code_for_user,
)
from secmind.auth.user_store import get_user_store
from secmind.env_shim import apply_integrations_for_request
from secmind.integration_store import get_store
from secmind.integration_tests import test_connection
from secmind.llm_credentials import lookup_api_key_for_model
from secmind.settings_store import get_settings_store
from secmind.reports import user_reports_dir
from secmind.user_context import user_scope

logger = logging.getLogger(__name__)

APP_NAME = "secmind"
DEFAULT_SESSION_ID = "default"

app = Flask(__name__)
# supports_credentials=True is required for the auth cookie to ride along on
# cross-origin requests from the Vite dev server (5173 → 5001).
#
# Two env knobs let prod / non-default setups override:
#   CORS_ORIGINS       — comma-separated exact origins (e.g. https://app.example.com)
#   CORS_ORIGIN_REGEX  — single regex; matches origins not in CORS_ORIGINS
#
# The default regex covers ``vite --host`` on the LAN (any IP/hostname on
# :5173) so signup/login work whether you hit localhost, 127.0.0.1, or your
# machine's LAN IP.
_is_dev = os.environ.get("SECMIND_ENV", "development") == "development"
_cors_default = "http://localhost:5173,http://127.0.0.1:5173" if _is_dev else ""
_origins: list = [
    o.strip()
    for o in os.environ.get("CORS_ORIGINS", _cors_default).split(",")
    if o.strip()
]
_origin_regex = os.environ.get(
    "CORS_ORIGIN_REGEX",
    r"^http://[\w.-]+:5173$" if _is_dev else "",
)
if _origin_regex:
    _origins.append(re.compile(_origin_regex))
CORS(app, supports_credentials=True, origins=_origins)

limiter = Limiter(get_remote_address, app=app, storage_uri="memory://")

_session_service = DatabaseSessionService(db_url="sqlite+aiosqlite:///memory/sessions.db")
_runner = Runner(app_name=APP_NAME, agent=secmind, session_service=_session_service)


def _all_agents() -> list:
    from google.adk.tools.agent_tool import AgentTool
    workers = [t.agent for t in (secmind.tools or []) if isinstance(t, AgentTool)]
    return [secmind, *workers]


def _resolve_model(model_id: str, user_id: int | None = None):
    """Return an ADK-compatible model handle for a model id string.

    - Gemini ids stay as plain strings (ADK native).
    - Claude/OpenAI ids are wrapped with LiteLlm. When ``user_id`` is given,
      the api_key is pulled from that user's active integration and passed
      directly to ``LiteLlm`` so the LLM path doesn't depend on the process-
      global env shim — that's the per-user-credentials race fix.
    - Without ``user_id`` we fall back to whatever LiteLlm finds in env, which
      is fine for single-tenant uses (CLI / ``adk web``).
    """
    if model_id.startswith("gemini"):
        return model_id
    if model_id.startswith("claude"):
        prefixed = f"anthropic/{model_id}"
    elif model_id.startswith("gpt-") or model_id.startswith("o"):
        prefixed = f"openai/{model_id}"
    else:
        prefixed = model_id
    kwargs: dict = {}
    if user_id is not None:
        api_key = lookup_api_key_for_model(model_id, user_id)
        if api_key:
            kwargs["api_key"] = api_key
    return LiteLlm(model=prefixed, **kwargs)


def _model_id(handle) -> str:
    """Reverse of _resolve_model — extract the bare id from an agent.model."""
    if isinstance(handle, str):
        return handle
    name = getattr(handle, "model", None)
    if isinstance(name, str):
        return name.split("/", 1)[-1]  # strip "anthropic/" / "openai/" prefix
    return str(handle)


@contextmanager
def _apply_user_model_settings(user_id: int):
    """Apply ``user_id``'s saved model selections to the live agent objects
    for the duration of the with-block, restoring the prior values on exit.

    Agent objects are process-globals, so concurrent requests from different
    users would race here — same caveat as the env shim. Acceptable for the
    single-process dev / single-tenant deployments this code targets today.
    """
    selections = get_settings_store().get_models(user_id)
    backup: list[tuple[object, object]] = []
    try:
        if selections:
            for agent in _all_agents():
                chosen = selections.get(agent.name)
                if chosen and _model_id(getattr(agent, "model", None)) != chosen:
                    backup.append((agent, agent.model))
                    agent.model = _resolve_model(chosen, user_id=user_id)
                    logger.info(
                        "Set %s model -> %s (user_id=%s)",
                        agent.name, chosen, user_id,
                    )
        yield
    finally:
        for agent, prev in backup:
            agent.model = prev


async def _ensure_session(user_id: str, session_id: str) -> None:
    existing = await _session_service.get_session(
        app_name=APP_NAME, user_id=user_id, session_id=session_id
    )
    if existing is None:
        await _session_service.create_session(
            app_name=APP_NAME, user_id=user_id, session_id=session_id
        )


async def _run_agent(user_message: str, user_id: str, session_id: str) -> dict:
    await _ensure_session(user_id, session_id)
    content = types.Content(role="user", parts=[types.Part(text=user_message)])

    final_text = ""
    last_author = None
    async for event in _runner.run_async(
        user_id=user_id, session_id=session_id, new_message=content
    ):
        if event.is_final_response() and event.content and event.content.parts:
            text = "".join(p.text or "" for p in event.content.parts).strip()
            if text:
                final_text = text
                last_author = event.author

    return {"response": final_text, "agent": last_author}


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------


def _maybe_claim_orphans_for_first_admin(user) -> None:
    """Reassign pre-multitenant data (orphan integrations parked at user_id=0
    by the AU5 migration) to the first admin to sign up.

    No-op when the new user isn't the first admin, so it's safe to call from
    every signup path. Best-effort: failures are logged, never raised, since
    a fresh deployment has nothing to claim and shouldn't fail signup over
    a missing orphan-claim.
    """
    if user.role != "admin" or get_user_store().count() != 1:
        return
    try:
        n = get_store().claim_orphans(user.id)
    except Exception:
        logger.exception("Failed to claim orphan integrations for user_id=%s", user.id)
        return
    if n:
        logger.info(
            "First admin user_id=%s claimed %d orphan integration(s)",
            user.id, n,
        )


@app.route("/auth/signup", methods=["POST"])
@limiter.limit("5/minute")
def auth_signup():
    data = request.get_json() or {}
    try:
        user = get_user_store().create_with_password(
            data.get("email", ""),
            data.get("password", ""),
            data.get("name"),
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    _maybe_claim_orphans_for_first_admin(user)
    resp = jsonify({"user": user.to_dict()})
    return set_session_cookie(resp, user)


@app.route("/auth/login", methods=["POST"])
@limiter.limit("10/minute")
def auth_login():
    data = request.get_json() or {}
    user = get_user_store().verify_password(
        data.get("email", ""), data.get("password", "")
    )
    if user is None:
        return jsonify({"error": "Invalid email or password"}), 401
    resp = jsonify({"user": user.to_dict()})
    return set_session_cookie(resp, user)


@app.route("/auth/logout", methods=["POST"])
def auth_logout():
    revoke_token(request.cookies.get(SESSION_COOKIE_NAME, ""))
    return clear_session_cookie(jsonify({"ok": True}))


@app.route("/auth/me", methods=["GET"])
@require_auth
def auth_me():
    return jsonify({"user": g.user.to_dict()})


@app.route("/auth/google/start", methods=["GET"])
def auth_google_start():
    try:
        url, state = build_authorize_url()
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 500
    resp = redirect(url, code=302)
    _cookie_default = "0" if os.environ.get("SECMIND_ENV", "development") == "development" else "1"
    secure = os.environ.get("SECMIND_COOKIE_SECURE", _cookie_default) == "1"
    resp.set_cookie(
        STATE_COOKIE,
        state,
        max_age=STATE_TTL_SECONDS,
        httponly=True,
        secure=secure,
        samesite="Lax",
        path="/auth/google",
    )
    return resp


@app.route("/auth/google/callback", methods=["GET"])
def auth_google_callback():
    error = request.args.get("error")
    if error:
        return jsonify({"error": f"Google OAuth: {error}"}), 400

    expected_state = request.cookies.get(STATE_COOKIE, "")
    received_state = request.args.get("state", "")
    if not expected_state or expected_state != received_state:
        return jsonify({"error": "OAuth state mismatch"}), 400

    code = request.args.get("code", "")
    if not code:
        return jsonify({"error": "missing code"}), 400

    try:
        user = exchange_code_for_user(code)
    except Exception as exc:
        logger.exception("Google OAuth callback failed")
        return jsonify({"error": str(exc)}), 400

    _maybe_claim_orphans_for_first_admin(user)

    # Redirect into the SPA root; the SPA bootstraps via /auth/me.
    spa_origin = (_origins[0] if _origins else "/").rstrip("/")
    resp = redirect(spa_origin + "/", code=302)
    resp.delete_cookie(STATE_COOKIE, path="/auth/google")
    return set_session_cookie(resp, user)


# ---------------------------------------------------------------------------
# Chat
# ---------------------------------------------------------------------------


@app.route("/chat", methods=["POST"])
@require_auth
def chat():
    data = request.get_json() or {}
    user_message = data.get("message")
    if not user_message:
        return jsonify({"error": "No message provided"}), 400

    # Use the authenticated user's id as the ADK session user_id so each user's
    # agent state is isolated. session_id is per-conversation (set by frontend).
    user_id = str(g.user.id)
    session_id = data.get("session_id") or DEFAULT_SESSION_ID

    try:
        # Bind the current user for sub-agent tools, project their active
        # integrations into env (e.g. ANTHROPIC_API_KEY, JIRA_*), and apply
        # their saved model selections to the live agents. All three revert
        # on exit so the next request starts from a clean baseline.
        with (
            user_scope(g.user.id),
            apply_integrations_for_request(g.user.id),
            _apply_user_model_settings(g.user.id),
        ):
            result = asyncio.run(_run_agent(user_message, user_id, session_id))
        return jsonify(result)
    except Exception as e:
        logger.exception("Agent run failed")
        return jsonify({"error": str(e)}), 500


@app.route("/settings/models", methods=["GET"])
@require_auth
def get_settings_models():
    selections = get_settings_store().get_models(g.user.id)
    agents = [
        {
            "id": a.name,
            "model": selections.get(a.name) or _model_id(getattr(a, "model", None)),
            "default": AgentConfig.MODEL,
        }
        for a in _all_agents()
    ]
    return jsonify({"agents": agents, "selections": selections})


@app.route("/settings/models", methods=["PUT"])
@require_auth
def put_settings_models():
    data = request.get_json() or {}
    selections = data.get("selections")
    if not isinstance(selections, dict):
        return jsonify({"error": "selections must be an object {agent_id: model_name}"}), 400

    valid_ids = {a.name for a in _all_agents()}
    bad = [k for k in selections if k not in valid_ids]
    if bad:
        return jsonify({"error": f"Unknown agent ids: {', '.join(bad)}"}), 400

    get_settings_store().set_models(g.user.id, selections)
    return get_settings_models()


@app.route("/integrations", methods=["GET"])
@require_auth
def list_integrations():
    return jsonify(get_store().list(g.user.id))


@app.route("/integrations", methods=["POST"])
@require_auth
def create_integration():
    data = request.get_json() or {}
    provider = data.get("provider")
    name = data.get("name")
    config = data.get("config")
    enabled = data.get("enabled", True)

    if not provider or not name or not isinstance(config, dict) or not config:
        return (
            jsonify({"error": "provider, name, and non-empty config are required"}),
            400,
        )

    try:
        rec = get_store().create(
            provider, name, config, user_id=g.user.id, enabled=bool(enabled)
        )
    except sqlite3.IntegrityError:
        return (
            jsonify({"error": f"Integration '{provider}/{name}' already exists"}),
            409,
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify(rec), 201


@app.route("/integrations/<int:integration_id>", methods=["GET"])
@require_auth
def get_integration(integration_id: int):
    rec = get_store().get(integration_id, g.user.id)
    if rec is None:
        return jsonify({"error": "Integration not found"}), 404
    return jsonify(rec)


@app.route("/integrations/<int:integration_id>", methods=["PUT", "PATCH"])
@require_auth
def update_integration(integration_id: int):
    data = request.get_json() or {}
    try:
        rec = get_store().update(
            integration_id,
            g.user.id,
            name=data.get("name"),
            enabled=data.get("enabled"),
            config=data.get("config"),
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    if rec is None:
        return jsonify({"error": "Integration not found"}), 404
    return jsonify(rec)


@app.route("/integrations/<int:integration_id>", methods=["DELETE"])
@require_auth
def delete_integration(integration_id: int):
    if not get_store().delete(integration_id, g.user.id):
        return jsonify({"error": "Integration not found"}), 404
    return "", 204


@app.route("/integrations/<int:integration_id>/test", methods=["POST"])
@require_auth
def test_integration(integration_id: int):
    rec = get_store().get(integration_id, g.user.id, decrypted=True)
    if rec is None:
        return jsonify({"error": "Integration not found"}), 404
    result = test_connection(rec["provider"], rec["config"])
    status_code = 200 if result.get("status") == "success" else 400
    return jsonify(result), status_code


REPORT_EXTENSIONS = (".html", ".pdf", ".json", ".md")


def _safe_filename(name: str) -> bool:
    return bool(name) and "/" not in name and "\\" not in name and ".." not in name


def _classify_report(name: str) -> str | None:
    n = name.lower()
    if n.startswith("compliance_report_"):
        return "cloud_compliance"
    if (
        n.startswith("threat model-")
        or "threatmodelreport" in n
        or "threat_model_report" in n
    ):
        return "threat_model"
    if n.startswith("endpoint_security_report-"):
        return "endpoint_security"
    return None


_TS_SUFFIX_RE = re.compile(r"-(\d{8}-\d{6})$")


def _report_title(name: str, kind: str) -> str:
    stem = os.path.splitext(name)[0]
    if kind == "cloud_compliance" and stem.startswith("compliance_report_"):
        body = stem[len("compliance_report_"):]
        m = _TS_SUFFIX_RE.search(body)
        if m:
            body = body[: m.start()]
        target = body.replace("_", "/")
        return f"Cloud compliance — {target}"
    if kind == "threat_model":
        if stem.startswith("Threat Model-"):
            return stem  # already a friendly display name
        if stem.startswith("securitymind-threatmodelreport-"):
            return f"Threat model — {stem[len('securitymind-threatmodelreport-'):]}"
        return "Threat model"
    if kind == "endpoint_security" and stem.startswith("endpoint_security_report-"):
        body = stem[len("endpoint_security_report-"):]
        m = _TS_SUFFIX_RE.search(body)
        ts = ""
        if m:
            ts = body[m.start() + 1:]
            body = body[: m.start()]
        integration = body or "default"
        return f"Endpoint security — {integration}" + (f" · {ts}" if ts else "")
    return stem


@app.route("/reports", methods=["GET"])
@require_auth
def list_reports():
    with user_scope(g.user.id):
        reports_dir = user_reports_dir()
    if not os.path.isdir(reports_dir):
        return jsonify([])

    items = []
    for name in os.listdir(reports_dir):
        if name.startswith("."):
            continue
        path = os.path.join(reports_dir, name)
        if not os.path.isfile(path):
            continue
        if not name.lower().endswith(REPORT_EXTENSIONS):
            continue
        kind = _classify_report(name)
        if kind is None:
            continue
        st = os.stat(path)
        items.append(
            {
                "id": name,
                "type": kind,
                "title": _report_title(name, kind),
                "size": st.st_size,
                "modified_at": datetime.fromtimestamp(
                    st.st_mtime, tz=timezone.utc
                ).isoformat(),
            }
        )

    items.sort(key=lambda r: r["modified_at"], reverse=True)
    return jsonify(items)


@app.route("/reports/<path:name>", methods=["GET"])
@require_auth
def get_report(name: str):
    if not _safe_filename(name):
        abort(404)
    with user_scope(g.user.id):
        reports_dir = user_reports_dir()
    if not os.path.isfile(os.path.join(reports_dir, name)):
        abort(404)
    download = request.args.get("download") == "1"
    return send_from_directory(reports_dir, name, as_attachment=download)


if __name__ == "__main__":
    app.run(port=5001, debug=True)
