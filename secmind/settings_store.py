"""
Settings store — JSON-backed per-user preferences for runtime-tunable values.

Today: per-agent model selection. Each user gets their own file at
``memory/settings/user_<id>.json``. The directory is gitignored alongside
the rest of ``memory/``.

A pre-multitenant ``memory/settings.json`` (single-tenant) may still exist
on disk; it is left alone (a future first-signup migration could claim it).
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from threading import RLock

logger = logging.getLogger(__name__)

DEFAULT_DIR = Path("memory/settings")


class SettingsStore:
    def __init__(self, base_dir: str | Path | None = None):
        self._dir = Path(base_dir) if base_dir else DEFAULT_DIR
        self._dir.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()

    def _path_for(self, user_id: int) -> Path:
        if not isinstance(user_id, int) or user_id <= 0:
            raise ValueError("user_id must be a positive integer")
        return self._dir / f"user_{user_id}.json"

    def _read(self, user_id: int) -> dict:
        path = self._path_for(user_id)
        if not path.exists():
            return {}
        try:
            return json.loads(path.read_text() or "{}")
        except Exception:
            logger.exception("Failed to read settings file %s", path)
            return {}

    def _write(self, user_id: int, data: dict) -> None:
        self._path_for(user_id).write_text(json.dumps(data, indent=2, sort_keys=True))

    def get_models(self, user_id: int) -> dict[str, str]:
        with self._lock:
            return dict(self._read(user_id).get("models", {}))

    def set_models(self, user_id: int, models: dict[str, str]) -> dict[str, str]:
        clean = {
            str(k): str(v).strip()
            for k, v in (models or {}).items()
            if isinstance(k, str) and isinstance(v, str) and v.strip()
        }
        with self._lock:
            data = self._read(user_id)
            data["models"] = clean
            self._write(user_id, data)
        return clean


_store: SettingsStore | None = None


def get_settings_store() -> SettingsStore:
    global _store
    if _store is None:
        _store = SettingsStore()
    return _store
