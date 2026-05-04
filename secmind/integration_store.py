"""
IntegrationStore — encrypted-at-rest credential store for third-party integrations.

Stores per-integration config (API keys, tokens, project IDs, etc.) as Fernet-encrypted
JSON blobs in SQLite. Records are scoped to the user who created them: every read/write
is filtered by ``user_id``. The HTTP layer in ``main.py`` passes ``g.user.id``;
sub-agent tool callers pull the active user from ``secmind.user_context``.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

DEFAULT_DB_DIR = "memory"
DB_FILENAME = "integrations.db"
KEY_FILENAME = ".fernet_key"
FERNET_ENV_VAR = "SECMIND_FERNET_KEY"

# Pre-multitenant rows have user_id = 0. They remain in the table but are not
# visible to any real user (auth user ids start at 1). Left for a later
# claim-on-first-signup migration; logged at startup so they don't get lost.
ORPHAN_USER_ID = 0


def _load_or_create_key(db_dir: Path) -> bytes:
    env_key = os.getenv(FERNET_ENV_VAR)
    if env_key:
        return env_key.encode("utf-8") if isinstance(env_key, str) else env_key

    key_path = db_dir / KEY_FILENAME
    if key_path.exists():
        return key_path.read_bytes().strip()

    logger.warning(
        "%s not set and %s missing — generating a new Fernet key. "
        "Set %s in production to avoid losing access to stored credentials.",
        FERNET_ENV_VAR, key_path, FERNET_ENV_VAR,
    )
    key = Fernet.generate_key()
    db_dir.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(key)
    try:
        os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return key


class IntegrationStore:
    """SQLite-backed store for integration credentials, encrypted with Fernet.

    Every record is owned by exactly one user (``user_id``). The unique
    constraint is ``(user_id, provider, name)`` so two users can each have
    their own integration named e.g. ``confluence/main`` without colliding.
    """

    def __init__(self, db_dir: str = DEFAULT_DB_DIR):
        self._db_dir = Path(db_dir)
        self._db_dir.mkdir(parents=True, exist_ok=True)

        self._fernet = Fernet(_load_or_create_key(self._db_dir))

        self._conn = sqlite3.connect(
            self._db_dir / DB_FILENAME, check_same_thread=False
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._setup()

    def _setup(self) -> None:
        # Fresh installs use the multi-tenant schema directly.
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS integrations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL DEFAULT 0,
                provider TEXT NOT NULL,
                name TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                config_encrypted BLOB NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(user_id, provider, name)
            )
            """
        )
        self._migrate_add_user_id()
        self._conn.commit()

    def _migrate_add_user_id(self) -> None:
        """Backfill ``user_id`` on legacy single-tenant rows."""
        cols = {
            r["name"]
            for r in self._conn.execute("PRAGMA table_info(integrations)").fetchall()
        }
        if "user_id" in cols:
            return

        logger.info("Migrating integrations table: adding user_id column")
        # SQLite's ALTER TABLE is limited; rebuild the table.
        self._conn.executescript(
            """
            ALTER TABLE integrations RENAME TO integrations_legacy;
            CREATE TABLE integrations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL DEFAULT 0,
                provider TEXT NOT NULL,
                name TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                config_encrypted BLOB NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(user_id, provider, name)
            );
            INSERT INTO integrations
                (id, user_id, provider, name, enabled, config_encrypted, created_at, updated_at)
            SELECT id, 0, provider, name, enabled, config_encrypted, created_at, updated_at
            FROM integrations_legacy;
            DROP TABLE integrations_legacy;
            """
        )
        orphans = self._conn.execute(
            "SELECT COUNT(*) FROM integrations WHERE user_id = ?", (ORPHAN_USER_ID,)
        ).fetchone()[0]
        if orphans:
            logger.warning(
                "Migrated %d pre-multitenant integration row(s) to user_id=0; "
                "they will be invisible until claimed.",
                orphans,
            )

    def _encrypt(self, config: dict) -> bytes:
        return self._fernet.encrypt(json.dumps(config, sort_keys=True).encode("utf-8"))

    def _decrypt(self, blob: bytes) -> dict:
        try:
            return json.loads(self._fernet.decrypt(blob).decode("utf-8"))
        except InvalidToken as exc:
            raise RuntimeError(
                "Failed to decrypt integration config — Fernet key mismatch. "
                f"Check {FERNET_ENV_VAR} or {self._db_dir / KEY_FILENAME}."
            ) from exc

    @staticmethod
    def _redact(row: sqlite3.Row, config: dict) -> dict:
        return {
            "id": row["id"],
            "provider": row["provider"],
            "name": row["name"],
            "enabled": bool(row["enabled"]),
            "fields": sorted(config.keys()),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def list(self, user_id: int) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM integrations WHERE user_id = ? ORDER BY provider, name",
            (user_id,),
        ).fetchall()
        return [self._redact(r, self._decrypt(r["config_encrypted"])) for r in rows]

    def get(
        self, integration_id: int, user_id: int, *, decrypted: bool = False
    ) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM integrations WHERE id = ? AND user_id = ?",
            (integration_id, user_id),
        ).fetchone()
        if not row:
            return None
        config = self._decrypt(row["config_encrypted"])
        if decrypted:
            return {**self._redact(row, config), "config": config}
        return self._redact(row, config)

    def create(
        self,
        provider: str,
        name: str,
        config: dict,
        *,
        user_id: int,
        enabled: bool = True,
    ) -> dict:
        if not provider or not name:
            raise ValueError("provider and name are required")
        if not isinstance(config, dict) or not config:
            raise ValueError("config must be a non-empty dict")
        if not isinstance(user_id, int) or user_id <= 0:
            raise ValueError("user_id must be a positive integer")

        now = datetime.now(timezone.utc).isoformat()
        cursor = self._conn.execute(
            """
            INSERT INTO integrations
                (user_id, provider, name, enabled, config_encrypted, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (user_id, provider, name, int(enabled), self._encrypt(config), now, now),
        )
        self._conn.commit()
        new_id = cursor.lastrowid
        logger.info(
            "Created integration %s/%s (id=%s, user_id=%s)",
            provider, name, new_id, user_id,
        )
        return self.get(new_id, user_id)  # type: ignore[return-value]

    def update(
        self,
        integration_id: int,
        user_id: int,
        *,
        name: str | None = None,
        enabled: bool | None = None,
        config: dict | None = None,
    ) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM integrations WHERE id = ? AND user_id = ?",
            (integration_id, user_id),
        ).fetchone()
        if not row:
            return None

        new_name = name if name is not None else row["name"]
        new_enabled = int(enabled) if enabled is not None else row["enabled"]
        if config is not None:
            if not isinstance(config, dict) or not config:
                raise ValueError("config must be a non-empty dict")
            new_blob = self._encrypt(config)
        else:
            new_blob = row["config_encrypted"]

        self._conn.execute(
            """
            UPDATE integrations
            SET name = ?, enabled = ?, config_encrypted = ?, updated_at = ?
            WHERE id = ? AND user_id = ?
            """,
            (
                new_name,
                new_enabled,
                new_blob,
                datetime.now(timezone.utc).isoformat(),
                integration_id,
                user_id,
            ),
        )
        self._conn.commit()
        return self.get(integration_id, user_id)

    def delete(self, integration_id: int, user_id: int) -> bool:
        cursor = self._conn.execute(
            "DELETE FROM integrations WHERE id = ? AND user_id = ?",
            (integration_id, user_id),
        )
        self._conn.commit()
        return cursor.rowcount > 0

    def iter_active(self, user_id: int) -> Iterator[dict]:
        rows = self._conn.execute(
            "SELECT * FROM integrations WHERE enabled = 1 AND user_id = ?",
            (user_id,),
        ).fetchall()
        for r in rows:
            yield {
                **self._redact(r, {}),
                "config": self._decrypt(r["config_encrypted"]),
            }


_default_store: IntegrationStore | None = None


def get_store() -> IntegrationStore:
    global _default_store
    if _default_store is None:
        _default_store = IntegrationStore()
    return _default_store
