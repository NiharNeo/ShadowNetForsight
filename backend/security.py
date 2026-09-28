from __future__ import annotations

import base64
import binascii
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time
from threading import RLock
from typing import Any


ROLE_LEVEL = {"viewer": 1, "operator": 2, "admin": 3}


@dataclass(frozen=True)
class Principal:
    username: str
    role: str


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class SecurityManager:
    def __init__(self, database: Path, secret: str | None = None) -> None:
        database.parent.mkdir(parents=True, exist_ok=True)
        self.database = database
        self._audit_health_lock = RLock()
        self._audit_health_cache = None
        self._audit_health_checked = 0.0
        configured = secret or os.environ.get("SHADOWNET_TOKEN_SECRET")
        secret_path = database.with_suffix(".secret")
        if configured is None:
            if secret_path.exists():
                configured = secret_path.read_text(encoding="utf-8").strip()
            else:
                configured = secrets.token_urlsafe(48)
                try:
                    fd = os.open(secret_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, "w") as stream:
                        stream.write(configured)
                except FileExistsError:
                    configured = secret_path.read_text(encoding="utf-8").strip()
        self.secret = configured.encode()
        self._initialize()
        self.database.chmod(0o600)

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.database, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, salt TEXT NOT NULL,
                    role TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp REAL NOT NULL, username TEXT NOT NULL,
                    action TEXT NOT NULL, resource TEXT NOT NULL, status INTEGER NOT NULL,
                    details TEXT NOT NULL, previous_hash TEXT NOT NULL, entry_hash TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS login_attempts (
                    client TEXT NOT NULL, username TEXT NOT NULL, timestamp REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS login_time ON login_attempts(timestamp);
            """)
            columns = {row[1] for row in db.execute("PRAGMA table_info(users)")}
            if "token_version" not in columns:
                db.execute("ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0")

    def allow_login(self, client: str, username: str, now: float | None = None) -> bool:
        """Shared across threads/restarts. Charge every attempt before PBKDF2."""
        now = time.time() if now is None else now
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM login_attempts WHERE timestamp <= ?", (now - 300,))
            count = db.execute("SELECT COUNT(*) FROM login_attempts WHERE client=?", (client,)).fetchone()[0]
            user_count = db.execute("SELECT COUNT(*) FROM login_attempts WHERE username=?", (username,)).fetchone()[0]
            total = db.execute("SELECT COUNT(*) FROM login_attempts").fetchone()[0]
            if count >= 20 or user_count >= 10 or total >= 1000:
                return False
            db.execute("INSERT INTO login_attempts VALUES(?,?,?)", (client, username, now))
            return True

    def create_user(self, username: str, password: str, role: str, replace: bool = False) -> None:
        if role not in ROLE_LEVEL or len(username) < 3 or len(password) < 10:
            raise ValueError("role must be viewer/operator/admin; username >=3 and password >=10 characters")
        salt = secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
        with self._connect() as db:
            statement = "INSERT INTO users(username,password_hash,salt,role,enabled,created_at) VALUES(?,?,?,?,1,?)"
            if replace:
                statement += " ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash, salt=excluded.salt, role=excluded.role, enabled=1, token_version=users.token_version+1"
            db.execute(statement, (username, _encode(digest), _encode(salt), role, time.time()))

    def authenticate(self, username: str, password: str) -> str | None:
        with self._connect() as db:
            row = db.execute("SELECT * FROM users WHERE username=? AND enabled=1", (username,)).fetchone()
        if row is None:
            hashlib.pbkdf2_hmac("sha256", password.encode(), b"0" * 16, 310_000)
            return None
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), _decode(row["salt"]), 310_000)
        if not hmac.compare_digest(_encode(actual), row["password_hash"]):
            return None
        return self.issue_token(Principal(row["username"], row["role"]), token_version=row["token_version"])

    def issue_token(self, principal: Principal, lifetime_seconds: int = 3600, token_version: int | None = None) -> str:
        with self._connect() as db:
            row = db.execute("SELECT token_version FROM users WHERE username=?", (principal.username,)).fetchone()
        payload = _encode(json.dumps({"sub": principal.username, "role": principal.role,
                                     "ver": token_version if token_version is not None else (row[0] if row else -1),
                                     "exp": int(time.time()) + lifetime_seconds,
                                     "nonce": secrets.token_hex(8)}, separators=(",", ":")).encode())
        signature = _encode(hmac.new(self.secret, payload.encode(), hashlib.sha256).digest())
        return f"{payload}.{signature}"

    def revoke_tokens(self, username: str) -> None:
        with self._connect() as db:
            db.execute("UPDATE users SET token_version=token_version+1 WHERE username=?", (username,))

    def verify_token(self, token: str) -> Principal | None:
        try:
            if not isinstance(token, str) or len(token) > 4096:
                return None
            payload, signature = token.split(".", 1)
            expected = _encode(hmac.new(self.secret, payload.encode(), hashlib.sha256).digest())
            if not hmac.compare_digest(signature, expected):
                return None
            claims = json.loads(_decode(payload))
            if not isinstance(claims, dict):
                return None
            if int(claims["exp"]) <= int(time.time()) or claims["role"] not in ROLE_LEVEL:
                return None
            with self._connect() as db:
                row = db.execute("SELECT role,enabled,token_version FROM users WHERE username=?", (claims["sub"],)).fetchone()
            if row is None or not row["enabled"] or row["role"] != claims["role"] or claims.get("ver") != row["token_version"]:
                return None
            return Principal(claims["sub"], claims["role"])
        except (ValueError, KeyError, TypeError, UnicodeError, binascii.Error, OverflowError):
            return None

    def audit(self, username: str, action: str, resource: str, status: int, details: dict[str, Any] | None = None) -> None:
        timestamp = time.time()
        detail_text = json.dumps(details or {}, sort_keys=True, separators=(",", ":"))
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
            previous_hash = previous[0] if previous else "0" * 64
            canonical = f"{timestamp}|{username}|{action}|{resource}|{status}|{detail_text}|{previous_hash}"
            entry_hash = hmac.new(self.secret, canonical.encode(), hashlib.sha256).hexdigest()
            db.execute("INSERT INTO audit_log(timestamp,username,action,resource,status,details,previous_hash,entry_hash) VALUES(?,?,?,?,?,?,?,?)",
                       (timestamp, username, action, resource, status, detail_text, previous_hash, entry_hash))

    def audit_entries(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (min(max(limit, 1), 1000),)).fetchall()
        return [dict(row) for row in rows]

    def audit_health(self) -> dict[str, Any]:
        """Readiness result, refreshed at most every five seconds per process."""
        with self._audit_health_lock:
            now = time.monotonic()
            if self._audit_health_cache is None or now - self._audit_health_checked >= 5:
                self._audit_health_cache = self.verify_audit_chain()
                self._audit_health_checked = time.monotonic()
            return dict(self._audit_health_cache)

    def verify_audit_chain(self) -> dict[str, Any]:
        previous_hash = "0" * 64
        entries, first_invalid = 0, None
        # Stream rows so verification memory does not grow with retained history.
        with self._connect() as db:
            for row in db.execute("SELECT * FROM audit_log ORDER BY id"):
                entries += 1
                canonical = f"{row['timestamp']}|{row['username']}|{row['action']}|{row['resource']}|{row['status']}|{row['details']}|{previous_hash}"
                expected = hmac.new(self.secret, canonical.encode(), hashlib.sha256).hexdigest()
                if row["previous_hash"] != previous_hash or not hmac.compare_digest(row["entry_hash"], expected):
                    if first_invalid is None:
                        first_invalid = row["id"]
                previous_hash = row["entry_hash"]
        return {"valid": first_invalid is None, "entries": entries, "first_invalid_id": first_invalid}

    def list_users(self) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute("SELECT username,role,enabled,created_at FROM users ORDER BY username").fetchall()
        return [dict(row) for row in rows]
