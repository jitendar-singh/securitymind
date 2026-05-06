"""Behave environment hooks — test isolation via temp DBs and Flask test client."""
import os
import shutil
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

os.environ.setdefault("SECMIND_ENV", "development")

import main
from secmind.auth import user_store as _user_store_mod
from secmind.auth import jwt_session as _jwt_mod
from secmind import integration_store as _int_store_mod
from secmind import settings_store as _settings_mod


def before_scenario(context, scenario):
    context.tmpdir = tempfile.mkdtemp(prefix="secmind_test_")
    tmp = Path(context.tmpdir)

    _user_store_mod._store = _user_store_mod.UserStore(db_path=tmp / "users.db")
    _int_store_mod._default_store = _int_store_mod.IntegrationStore(
        db_dir=str(tmp)
    )
    _settings_mod._store = _settings_mod.SettingsStore(base_dir=tmp / "settings")

    _jwt_mod._secret = "test-secret-for-behave-e2e-must-be-at-least-32-bytes-long"
    _jwt_mod.REVOCATION_DB = tmp / "revoked_tokens.db"
    _jwt_mod._revocation_store = None

    context.reports_dir = str(tmp / "reports")
    os.makedirs(context.reports_dir, exist_ok=True)

    main.limiter.reset()

    context._run_agent_patcher = patch(
        "main._run_agent",
        new_callable=AsyncMock,
        return_value={"response": "Test response from agent.", "agent": "secmind"},
    )
    context.mock_run_agent = context._run_agent_patcher.start()

    context.client = main.app.test_client()
    context.response = None
    context.saved_cookies = {}
    context._env_backup = {}
    context._patchers = []


def after_scenario(context, scenario):
    context._run_agent_patcher.stop()
    for p in getattr(context, "_patchers", []):
        p.stop()
    for key, val in getattr(context, "_env_backup", {}).items():
        if val is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = val
    shutil.rmtree(context.tmpdir, ignore_errors=True)


def before_feature(context, feature):
    pass


def after_feature(context, feature):
    pass
