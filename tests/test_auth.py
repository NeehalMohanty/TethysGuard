import time
import sqlite3

import pytest
from fastapi.testclient import TestClient

from Backend.auth import COOKIE_NAME, UserCreate, create_user, hash_password, token_digest, verify_password
from Backend.database import database_connection, initialize_database
from Backend.main import create_app

PASSWORD = "test-only password with spaces 42!"


@pytest.fixture
def auth_client(tmp_path):
    app = create_app(database_path=tmp_path / "auth.db")
    with TestClient(app) as client:
        for username, role in [("admin", "admin"), ("analyst", "analyst"), ("viewer", "viewer")]:
            create_user(app.state.database_path, UserCreate(username=username, password=PASSWORD, role=role))
        client.headers["X-TethysGuard-Request"] = "1"
        yield client


def login(client, username="admin", password=PASSWORD):
    result = client.post("/api/auth/login", json={"username": username, "password": password})
    assert result.status_code == 200, result.text
    client.headers["X-CSRF-Token"] = result.json()["csrf_token"]
    return result


def event(client):
    response = client.post("/api/events", json={"source_ip": "192.0.2.10", "event_type": "port_scan", "severity": "high"})
    assert response.status_code == 200
    return response.json()["alert_id"]


def test_password_hashes_are_salted_and_passwords_not_trimmed():
    first, second = hash_password(PASSWORD), hash_password(PASSWORD)
    assert first != second and PASSWORD not in first
    assert verify_password(PASSWORD, first)
    assert not verify_password("wrong", first)
    assert not verify_password(PASSWORD, "invalid")
    padded = " " + PASSWORD + " "
    assert verify_password(padded, hash_password(padded))
    assert not verify_password(PASSWORD, hash_password(padded))


@pytest.mark.parametrize("method,url,body", [
    ("get", "/api/events", None), ("get", "/api/alerts", None),
    ("get", "/api/alerts/1", None), ("get", "/api/alerts/1/timeline", None),
    ("get", "/api/alerts/1/events", None), ("get", "/api/alerts/1/history", None),
    ("get", "/api/dashboard/stats", None), ("get", "/api/auth/users", None),
    ("post", "/api/events", {}), ("post", "/api/ingest/batch", {}),
    ("patch", "/api/alerts/1", {"status": "resolved"}),
    ("post", "/api/alerts/1/notes", {"body": "Forged"}),
])
def test_unauthenticated_access_denied(auth_client, method, url, body):
    assert auth_client.request(method, url, json=body).status_code == 401


def test_login_cookie_storage_rotation_logout(auth_client):
    response = login(auth_client)
    assert set(response.json()["user"]) == {"id", "username", "role", "active"}
    assert "password" not in response.text
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and "path=/" in cookie
    assert response.headers["cache-control"] == "no-store"
    old = auth_client.cookies.get(COOKIE_NAME)
    with database_connection(auth_client.app.state.database_path) as connection:
        stored = connection.execute("SELECT token_hash FROM sessions").fetchone()[0]
        assert old not in stored and stored == token_digest(old)
    login(auth_client)
    assert auth_client.cookies.get(COOKIE_NAME) != old
    with database_connection(auth_client.app.state.database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1
    current = auth_client.cookies.get(COOKIE_NAME)
    assert auth_client.post("/api/auth/logout").status_code == 204
    auth_client.cookies.set(COOKIE_NAME, current)
    assert auth_client.get("/api/auth/me").status_code == 401


def test_expired_and_disabled_sessions(auth_client):
    login(auth_client)
    with database_connection(auth_client.app.state.database_path) as connection:
        connection.execute("UPDATE sessions SET expires_at = ?", (int(time.time()) - 1,))
    assert auth_client.get("/api/alerts").status_code == 401
    login(auth_client)
    with database_connection(auth_client.app.state.database_path) as connection:
        connection.execute("UPDATE users SET active = 0 WHERE username = 'admin'")
    assert auth_client.get("/api/auth/me").status_code == 401


@pytest.mark.parametrize("username,password", [("admin", "incorrect"), ("unknown", PASSWORD)])
def test_generic_login_failure(auth_client, username, password):
    response = auth_client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid username or password"


def test_login_throttle(auth_client):
    for _ in range(5):
        assert auth_client.post("/api/auth/login", json={"username": "admin", "password": "bad"}).status_code == 401
    assert auth_client.post("/api/auth/login", json={"username": "admin", "password": PASSWORD}).status_code == 429
    with database_connection(auth_client.app.state.database_path) as connection:
        connection.execute("UPDATE login_attempts SET attempted_at = ?", (int(time.time()) - 301,))
    login(auth_client)


def test_login_and_write_csrf(auth_client):
    payload = {"username": "admin", "password": PASSWORD}
    assert auth_client.post("/api/auth/login", json=payload, headers={"X-TethysGuard-Request": ""}).status_code == 403
    assert auth_client.post("/api/auth/login", json=payload, headers={"Origin": "https://evil.example"}).status_code == 403
    login(auth_client)
    for headers in [{"X-CSRF-Token": ""}, {"X-CSRF-Token": "wrong"}, {"Origin": "https://evil.example"}]:
        assert auth_client.post("/api/auth/logout", headers=headers).status_code == 403
    assert auth_client.get("/api/auth/me").status_code == 200
    assert auth_client.post("/api/auth/logout", headers={"Origin": "http://localhost:5173"}).status_code == 204


@pytest.mark.parametrize("role", ["viewer", "analyst", "admin"])
def test_role_matrix_and_trusted_actor(auth_client, role):
    login(auth_client)
    alert_id = event(auth_client)
    login(auth_client, role)
    for url in ["/api/alerts", "/api/events", "/api/dashboard/stats", f"/api/alerts/{alert_id}/timeline"]:
        assert auth_client.get(url).status_code == 200
    expected = 403 if role == "viewer" else 200
    assert auth_client.patch(f"/api/alerts/{alert_id}", json={"status": "investigating", "actor": "impersonated"}).status_code == expected
    note = auth_client.post(f"/api/alerts/{alert_id}/notes", json={"body": "Investigated", "actor": "impersonated"})
    assert note.status_code == (403 if role == "viewer" else 201)
    if role != "viewer":
        assert note.json()["actor"] == role
        assert note.json()["actor_user_id"] == auth_client.get("/api/auth/me").json()["user"]["id"]
    assert auth_client.patch(f"/api/alerts/{alert_id}/assignment", json={"assigned_to": "analyst"}).status_code == expected
    assert auth_client.get("/api/auth/users").status_code == (200 if role == "admin" else 403)
    assert auth_client.post("/api/auth/users", json={"username": "extra", "password": PASSWORD, "role": "viewer"}).status_code == (201 if role == "admin" else 403)
    assert auth_client.patch("/api/auth/users/2", json={"role": "viewer", "active": True}).status_code == (200 if role == "admin" else 403)
    assert auth_client.post("/api/events", json={"source_ip": "192.0.2.20", "event_type": "login"}).status_code == (200 if role == "admin" else 403)
    assert auth_client.post("/api/ingest/batch", json={"source": "security_event", "records": [{"source_ip": "192.0.2.20", "event_type": "login"}]}).status_code == (200 if role == "admin" else 403)


def test_account_management_and_immediate_revocation(auth_client):
    login(auth_client, "analyst")
    analyst_token = auth_client.cookies.get(COOKIE_NAME)
    login(auth_client)
    path = auth_client.app.state.database_path
    # Add a separate real analyst session to verify revocation by user ID.
    with TestClient(auth_client.app) as other:
        other.headers["X-TethysGuard-Request"] = "1"
        login(other, "analyst")
        analyst_token = other.cookies.get(COOKIE_NAME)
        result = auth_client.patch("/api/auth/users/2", json={"role": "viewer", "active": False})
        assert result.status_code == 200
        assert other.get("/api/alerts").status_code == 401
    with database_connection(path) as connection:
        assert connection.execute("SELECT 1 FROM sessions WHERE token_hash = ?", (token_digest(analyst_token),)).fetchone() is None
    assert auth_client.patch("/api/auth/users/1", json={"role": "viewer", "active": False}).status_code == 409
    assert auth_client.post("/api/auth/users", json={"username": "ADMIN", "password": PASSWORD, "role": "admin"}).status_code == 409
    assert auth_client.post("/api/auth/login", json={"username": "analyst", "password": PASSWORD}).status_code == 401


def test_password_change_revokes_all_sessions(auth_client):
    login(auth_client)
    token = auth_client.cookies.get(COOKIE_NAME)
    assert auth_client.post("/api/auth/password", json={"current_password": "bad", "new_password": PASSWORD + "new"}).status_code == 400
    assert auth_client.post("/api/auth/password", json={"current_password": PASSWORD, "new_password": PASSWORD + "new"}).status_code == 204
    auth_client.cookies.set(COOKIE_NAME, token)
    assert auth_client.get("/api/auth/me").status_code == 401
    auth_client.cookies.clear()
    assert auth_client.post("/api/auth/login", json={"username": "admin", "password": PASSWORD}).status_code == 401
    login(auth_client, password=PASSWORD + "new")


def test_invalid_secret_not_echoed_and_password_policy(auth_client):
    login(auth_client)
    secret = "short-secret"
    result = auth_client.post("/api/auth/users", json={"username": "newuser", "password": secret, "role": "admin"})
    assert result.status_code == 422 and secret not in result.text
    assert auth_client.post("/api/auth/users", json={"username": "newuser", "password": PASSWORD, "role": "superuser"}).status_code == 422


def test_assignment_requires_active_analyst_account(auth_client):
    login(auth_client)
    alert_id = event(auth_client)
    for name in ("unknown", "viewer"):
        assert auth_client.patch(f"/api/alerts/{alert_id}/assignment", json={"assigned_to": name}).status_code == 422
    assert auth_client.patch(f"/api/alerts/{alert_id}/assignment", json={"assigned_to": "ANALYST"}).json()["alert"]["assigned_to"] == "analyst"


def test_bootstrap_closed_and_initialization_preserves_accounts(auth_client):
    path = auth_client.app.state.database_path
    with pytest.raises(ValueError, match="bootstrap is disabled"):
        create_user(path, UserCreate(username="intruder", password=PASSWORD, role="admin"), bootstrap=True)
    initialize_database(path)
    login(auth_client)
    assert len(auth_client.get("/api/auth/users").json()) == 3


def test_secure_cookie_configuration(auth_client, monkeypatch):
    from dataclasses import replace
    from Backend.config import settings
    monkeypatch.setattr("Backend.routes.auth.settings", replace(settings, session_cookie_secure=True))
    response = auth_client.post("/api/auth/login", json={"username": "admin", "password": PASSWORD})
    assert response.status_code == 200
    assert "; Secure" in response.headers["set-cookie"]


def test_phase8_upgrade_preserves_unverified_notes_and_assignments(tmp_path):
    path = tmp_path / "phase8.db"
    with sqlite3.connect(path) as connection:
        connection.executescript("""
            CREATE TABLE events (
                id INTEGER PRIMARY KEY, source_ip TEXT, destination_ip TEXT, event_type TEXT,
                username TEXT, severity TEXT, message TEXT, timestamp TEXT
            );
            CREATE TABLE alerts (
                id INTEGER PRIMARY KEY, event_id INTEGER, title TEXT, description TEXT,
                severity TEXT, status TEXT, timestamp TEXT, assigned_to TEXT, resolution TEXT
            );
            CREATE TABLE alert_activity (
                id INTEGER PRIMARY KEY, alert_id INTEGER, action TEXT, actor TEXT,
                details TEXT, created_at TEXT, status_history_id INTEGER UNIQUE
            );
            INSERT INTO events VALUES (1, '192.0.2.10', NULL, 'port_scan', NULL, 'high', NULL, '2026-01-01');
            INSERT INTO alerts VALUES (1, 1, 'Old alert', 'Evidence', 'high', 'open', '2026-01-01', 'Old label', NULL);
            INSERT INTO alert_activity VALUES (1, 1, 'note_added', 'Old label', '{"body":"Original note"}', '2026-01-02', NULL);
        """)
    initialize_database(path)
    initialize_database(path)
    with database_connection(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
        note = connection.execute("SELECT * FROM alert_activity").fetchone()
        assert note["actor"] == "Old label" and note["actor_user_id"] is None
        assert note["details"] == '{"body":"Original note"}'
        assert connection.execute("SELECT assigned_to FROM alerts").fetchone()[0] == "Old label"
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_local_bootstrap_and_password_recovery(tmp_path, monkeypatch):
    from dataclasses import replace
    from Backend import manage_users
    path = tmp_path / "cli.db"
    monkeypatch.setattr(manage_users, "settings", replace(manage_users.settings, database_path=path))
    monkeypatch.setattr("sys.argv", ["manage_users", "bootstrap", "--username", "admin"])
    monkeypatch.setattr(manage_users, "getpass", lambda _: PASSWORD)
    manage_users.main()
    with database_connection(path) as connection:
        account = connection.execute("SELECT * FROM users").fetchone()
        assert account["role"] == "admin" and verify_password(PASSWORD, account["password_hash"])
    with pytest.raises(SystemExit):
        manage_users.main()
    monkeypatch.setattr("sys.argv", ["manage_users", "reset-password", "--username", "admin"])
    monkeypatch.setattr(manage_users, "getpass", lambda _: PASSWORD + " changed")
    manage_users.main()
    with database_connection(path) as connection:
        stored = connection.execute("SELECT password_hash FROM users").fetchone()[0]
        assert verify_password(PASSWORD + " changed", stored)
        assert not verify_password(PASSWORD, stored)
