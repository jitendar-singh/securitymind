"""SQLite-backed user account store.

Lives at ``memory/users.db`` (separate from the encrypted ``integrations.db`` so
password hashes and credential ciphertext never share a DB file). Passwords are
hashed with bcrypt directly (12 rounds). bcrypt has a 72-byte password limit —
inputs are truncated at that boundary, matching the algorithm's behaviour and
giving the library nothing to refuse.
"""
from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Optional

import bcrypt

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = Path("memory/users.db")


@dataclass
class User:
    id: int
    email: str
    name: Optional[str]
    role: str

    def to_dict(self) -> dict:
        return {"id": self.id, "email": self.email, "name": self.name, "role": self.role}


class UserStore:
    def __init__(self, db_path: str | Path | None = None):
        self._path = Path(db_path) if db_path else DEFAULT_DB_PATH
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._setup()

    def _setup(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT,
                google_sub TEXT UNIQUE,
                name TEXT,
                role TEXT NOT NULL DEFAULT 'user',
                created_at TEXT NOT NULL,
                last_login_at TEXT,
                billing_customer_id TEXT
            )
            """
        )
        self._conn.commit()

    @staticmethod
    def _row_to_user(row: sqlite3.Row | None) -> Optional[User]:
        if row is None:
            return None
        return User(id=row["id"], email=row["email"], name=row["name"], role=row["role"])

    def count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) FROM users").fetchone()[0])

    def get(self, user_id: int) -> Optional[User]:
        return self._row_to_user(
            self._conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        )

    def get_by_email(self, email: str) -> Optional[User]:
        return self._row_to_user(
            self._conn.execute(
                "SELECT * FROM users WHERE email = ?", (email.strip().lower(),)
            ).fetchone()
        )

    def _next_role(self) -> str:
        # First user becomes admin so the first-signup migration can attach
        # pre-existing single-tenant data to them.
        return "admin" if self.count() == 0 else "user"

    @staticmethod
    def _hash_password(password: str) -> str:
        # bcrypt accepts up to 72 bytes; truncate to match the algorithm.
        pw = (password or "").encode("utf-8")[:72]
        return bcrypt.hashpw(pw, bcrypt.gensalt(rounds=12)).decode("utf-8")

    @staticmethod
    def _check_password(password: str, hashed: str) -> bool:
        try:
            return bcrypt.checkpw(
                (password or "").encode("utf-8")[:72],
                (hashed or "").encode("utf-8"),
            )
        except (ValueError, TypeError):
            return False

    def create_with_password(self, email: str, password: str, name: str | None = None) -> User:
        email = (email or "").strip().lower()
        if not email or "@" not in email:
            raise ValueError("Valid email required")
        if not password or len(password) < 8:
            raise ValueError("Password must be at least 8 characters")

        with self._lock:
            if self.get_by_email(email) is not None:
                raise ValueError("An account with that email already exists")
            now = datetime.now(timezone.utc).isoformat()
            cur = self._conn.execute(
                """
                INSERT INTO users (email, password_hash, name, role, created_at, last_login_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (email, self._hash_password(password), (name or "").strip() or None, self._next_role(), now, now),
            )
            self._conn.commit()
            user = self.get(cur.lastrowid)
            assert user is not None
            logger.info("Created user %s (id=%s, role=%s)", email, user.id, user.role)
            return user

    def verify_password(self, email: str, password: str) -> Optional[User]:
        email = (email or "").strip().lower()
        row = self._conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if row is None or not row["password_hash"]:
            return None
        if not self._check_password(password, row["password_hash"]):
            return None
        self._touch_login(row["id"])
        return self._row_to_user(row)

    def get_or_create_oauth(
        self, provider: str, sub: str, email: str, name: str | None = None
    ) -> User:
        if provider != "google":
            raise ValueError(f"Unsupported OAuth provider: {provider}")
        if not sub:
            raise ValueError("OAuth sub is required")
        email = (email or "").strip().lower()
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM users WHERE google_sub = ?", (sub,)
            ).fetchone()
            if row:
                self._touch_login(row["id"])
                return self._row_to_user(row)  # type: ignore[return-value]

            # Match an existing email-account if the user originally signed up
            # with email+password — link the Google sub to it instead of
            # creating a duplicate row.
            row = self._conn.execute(
                "SELECT * FROM users WHERE email = ?", (email,)
            ).fetchone()
            if row:
                self._conn.execute(
                    "UPDATE users SET google_sub = ?, last_login_at = ? WHERE id = ?",
                    (sub, datetime.now(timezone.utc).isoformat(), row["id"]),
                )
                self._conn.commit()
                return self._row_to_user(
                    self._conn.execute("SELECT * FROM users WHERE id = ?", (row["id"],)).fetchone()
                )  # type: ignore[return-value]

            now = datetime.now(timezone.utc).isoformat()
            cur = self._conn.execute(
                """
                INSERT INTO users (email, google_sub, name, role, created_at, last_login_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (email, sub, (name or "").strip() or None, self._next_role(), now, now),
            )
            self._conn.commit()
            user = self.get(cur.lastrowid)
            assert user is not None
            logger.info("Created OAuth user %s (id=%s, role=%s)", email, user.id, user.role)
            return user

    def _touch_login(self, user_id: int) -> None:
        self._conn.execute(
            "UPDATE users SET last_login_at = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), user_id),
        )
        self._conn.commit()


_store: Optional[UserStore] = None


def get_user_store() -> UserStore:
    global _store
    if _store is None:
        _store = UserStore()
    return _store
