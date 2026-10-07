"""Local-account authentication with revocable, hashed server-side sessions."""
from datetime import datetime, timezone
import hashlib
import hmac
import secrets
import sqlite3
import time
from typing import Annotated, Literal

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from Backend.config import settings
from Backend.database import database_connection

COOKIE_NAME = "tethysguard_session"
SESSION_SECONDS = 8 * 60 * 60
Role = Literal["admin", "analyst", "viewer"]


class Credentials(BaseModel):
    # Do not trim or normalize passwords.
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=3, max_length=50, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    password: SecretStr = Field(min_length=1, max_length=128)

    @field_validator("username", mode="before")
    @classmethod
    def normalize_username(cls, value):
        return value.strip().lower() if isinstance(value, str) else value


class UserCreate(Credentials):
    password: SecretStr = Field(min_length=15, max_length=128)
    role: Role


class UserUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Role
    active: bool = Field(strict=True)


class PasswordChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    current_password: SecretStr = Field(min_length=1, max_length=128)
    new_password: SecretStr = Field(min_length=15, max_length=128)


class UserPublic(BaseModel):
    id: int
    username: str
    role: Role
    active: bool


class SessionPublic(BaseModel):
    user: UserPublic
    csrf_token: str


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    key = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=5, dklen=32)
    return f"scrypt$16384$8$5${salt.hex()}${key.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, n, r, p, salt, expected = stored.split("$")
        if (algorithm, n, r, p) != ("scrypt", "16384", "8", "5"):
            return False
        actual = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt),
                                n=16384, r=8, p=5, dklen=32)
        return hmac.compare_digest(actual, bytes.fromhex(expected))
    except (ValueError, TypeError):
        return False


# Unknown users still pay the same password-verification cost.
DUMMY_HASH = hash_password(secrets.token_urlsafe(32))


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def audit(connection, actor_id, target_id, action):
    connection.execute("""
        INSERT INTO account_audit (actor_user_id, target_user_id, action, created_at)
        VALUES (?, ?, ?, ?)
    """, (actor_id, target_id, action, datetime.now(timezone.utc).isoformat()))


def create_user(path, data: UserCreate, *, actor_id=None, bootstrap=False):
    password_hash = hash_password(data.password.get_secret_value())
    with database_connection(path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        if bootstrap and connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
            raise ValueError("Accounts already exist; bootstrap is disabled")
        try:
            cursor = connection.execute("""
                INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)
            """, (data.username, password_hash, data.role, datetime.now(timezone.utc).isoformat()))
        except sqlite3.IntegrityError as error:
            raise ValueError("Username is already in use") from error
        audit(connection, actor_id, cursor.lastrowid, "user_created")
        return dict(connection.execute("SELECT id, username, role, active FROM users WHERE id = ?",
                                       (cursor.lastrowid,)).fetchone())


def check_origin(request: Request):
    origin = request.headers.get("origin")
    if origin is not None and origin not in settings.cors_origins:
        raise HTTPException(status_code=403, detail="Request origin is not allowed")


def current_user(request: Request):
    token = request.cookies.get(COOKIE_NAME, "")
    if not token or len(token) > 200:
        raise HTTPException(status_code=401, detail="Sign in required")
    digest = token_digest(token)
    with database_connection(request.app.state.database_path) as connection:
        row = connection.execute("""
            SELECT u.id, u.username, u.role, u.active, s.csrf_token, s.expires_at
            FROM sessions s JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = ? AND u.active = 1 AND s.expires_at > ?
        """, (digest, int(time.time()))).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="Session expired; sign in again")
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        check_origin(request)
        supplied = request.headers.get("x-csrf-token", "")
        if not hmac.compare_digest(supplied.encode(), row["csrf_token"].encode()):
            raise HTTPException(status_code=403, detail="Invalid CSRF token")
    return {**dict(row), "token_hash": digest}


def require_roles(*roles):
    def dependency(user=Depends(current_user)):
        if user["role"] not in roles:
            raise HTTPException(status_code=403, detail="Your role does not allow this action")
        return user
    return dependency


CurrentUser = Annotated[dict, Depends(current_user)]
AnalystUser = Annotated[dict, Depends(require_roles("admin", "analyst"))]
AdminUser = Annotated[dict, Depends(require_roles("admin"))]


def authenticate(path, credentials: Credentials, source: str, previous_token: str = ""):
    now = int(time.time())
    with database_connection(path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("DELETE FROM login_attempts WHERE attempted_at <= ?", (now - 300,))
        counts = connection.execute("""
            SELECT SUM(username = ?) AS account, SUM(source = ?) AS source FROM login_attempts
        """, (credentials.username, source)).fetchone()
        if (counts["account"] or 0) >= 5 or (counts["source"] or 0) >= 20:
            raise HTTPException(status_code=429, detail="Too many login attempts; try again in 5 minutes",
                                headers={"Retry-After": "300"})
        connection.execute("INSERT INTO login_attempts (username, source, attempted_at) VALUES (?, ?, ?)",
                           (credentials.username, source, now))
        row = connection.execute("SELECT * FROM users WHERE username = ?", (credentials.username,)).fetchone()
    valid = verify_password(credentials.password.get_secret_value(), row["password_hash"] if row else DUMMY_HASH)
    if not valid or row is None or not row["active"]:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    with database_connection(path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        latest = connection.execute("SELECT * FROM users WHERE id = ?", (row["id"],)).fetchone()
        if not latest["active"] or latest["password_hash"] != row["password_hash"]:
            raise HTTPException(status_code=401, detail="Invalid username or password")
        connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
        if previous_token:
            connection.execute("DELETE FROM sessions WHERE token_hash = ?", (token_digest(previous_token),))
        connection.execute("INSERT INTO sessions VALUES (?, ?, ?, ?)",
                           (token_digest(token), row["id"], csrf, now + SESSION_SECONDS))
        audit(connection, row["id"], row["id"], "login")
    return token, {"user": dict(latest), "csrf_token": csrf}
