from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time
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
        configured = secret or os.environ.get("SHADOWNET_TOKEN_SECRET")
        secret_path = database.with_suffix(".secret")
        if configured is None:
            if secret_path.exists():
                configured = secret_path.read_text(encoding="utf-8").strip()
            else:
                configured = secrets.token_urlsafe(48)
                secret_path.write_text(configured, encoding="utf-8")
                secret_path.chmod(0o600)
        self.secret = configured.encode()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

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
            """)

    def create_user(self, username: str, password: str, role: str, replace: bool = False) -> None:
        if role not in ROLE_LEVEL or len(username) < 3 or len(password) < 10:
            raise ValueError("role must be viewer/operator/admin; username >=3 and password >=10 characters")
        salt = secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
        verb = "INSERT OR REPLACE" if replace else "INSERT"
        with self._connect() as db:
            db.execute(f"{verb} INTO users(username,password_hash,salt,role,enabled,created_at) VALUES(?,?,?,?,1,?)",
                       (username, _encode(digest), _encode(salt), role, time.time()))

    def authenticate(self, username: str, password: str) -> str | None:
        with self._connect() as db:
            row = db.execute("SELECT * FROM users WHERE username=? AND enabled=1", (username,)).fetchone()
        if row is None:
            hashlib.pbkdf2_hmac("sha256", password.encode(), b"0" * 16, 310_000)
            return None
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), _decode(row["salt"]), 310_000)
        if not hmac.compare_digest(_encode(actual), row["password_hash"]):
            return None
        return self.issue_token(Principal(row["username"], row["role"]))

    def issue_token(self, principal: Principal, lifetime_seconds: int = 3600) -> str:
        payload = _encode(json.dumps({"sub": principal.username, "role": principal.role,
                                     "exp": int(time.time()) + lifetime_seconds,
                                     "nonce": secrets.token_hex(8)}, separators=(",", ":")).encode())
        signature = _encode(hmac.new(self.secret, payload.encode(), hashlib.sha256).digest())
        return f"{payload}.{signature}"

    def verify_token(self, token: str) -> Principal | None:
        try:
            payload, signature = token.split(".", 1)
            expected = _encode(hmac.new(self.secret, payload.encode(), hashlib.sha256).digest())
            if not hmac.compare_digest(signature, expected):
                return None
            claims = json.loads(_decode(payload))
            if int(claims["exp"]) < int(time.time()) or claims["role"] not in ROLE_LEVEL:
                return None
            with self._connect() as db:
                row = db.execute("SELECT role,enabled FROM users WHERE username=?", (claims["sub"],)).fetchone()
            if row is None or not row["enabled"] or row["role"] != claims["role"]:
                return None
            return Principal(claims["sub"], claims["role"])
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            return None

    def audit(self, username: str, action: str, resource: str, status: int, details: dict[str, Any] | None = None) -> None:
        timestamp = time.time()
        detail_text = json.dumps(details or {}, sort_keys=True, separators=(",", ":"))
        with self._connect() as db:
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

    def verify_audit_chain(self) -> dict[str, Any]:
        with self._connect() as db:
            rows = db.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
        previous_hash = "0" * 64
        for row in rows:
            canonical = f"{row['timestamp']}|{row['username']}|{row['action']}|{row['resource']}|{row['status']}|{row['details']}|{previous_hash}"
            expected = hmac.new(self.secret, canonical.encode(), hashlib.sha256).hexdigest()
            if row["previous_hash"] != previous_hash or not hmac.compare_digest(row["entry_hash"], expected):
                return {"valid": False, "entries": len(rows), "first_invalid_id": row["id"]}
            previous_hash = row["entry_hash"]
        return {"valid": True, "entries": len(rows), "first_invalid_id": None}

    def list_users(self) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute("SELECT username,role,enabled,created_at FROM users ORDER BY username").fetchall()
        return [dict(row) for row in rows]
