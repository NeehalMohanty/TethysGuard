import asyncio
import sqlite3
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from Backend import live
from Backend.auth import COOKIE_NAME, token_digest
from Backend.database import database_connection, initialize_database


def identity(client):
    return client.app.state.database_path, token_digest(client.cookies.get(COOKIE_NAME))


def revision(client):
    return live.live_revision(*identity(client))


def create_alert(client):
    response = client.post("/api/events", json={
        "source_ip": "192.0.2.10", "event_type": "port_scan", "severity": "high",
    })
    assert response.status_code == 200
    return response.json()["alert_id"]


def test_revision_tracks_committed_events_workflow_and_grouped_evidence(client):
    previous = revision(client)
    alert_id = create_alert(client)
    assert revision(client) > previous
    for suffix, method, body in [
        ("", "patch", {"status": "investigating"}),
        ("/assignment", "patch", {"assigned_to": "analyst-a"}),
        ("/notes", "post", {"body": "Checked host evidence"}),
    ]:
        previous = revision(client)
        assert getattr(client, method)(f"/api/alerts/{alert_id}{suffix}", json=body).is_success
        assert revision(client) > previous
    previous = revision(client)
    create_alert(client)  # Suppressed alert still adds event/grouping evidence.
    assert revision(client) > previous
    assert client.get(f"/api/alerts/{alert_id}/events").json()["count"] >= 2


def test_failed_writes_do_not_publish_and_partial_batch_does(client):
    previous = revision(client)
    with pytest.raises(RuntimeError):
        with database_connection(client.app.state.database_path) as connection:
            connection.execute("""
                INSERT INTO events (source_ip, event_type, severity, timestamp)
                VALUES ('192.0.2.9', 'login_success', 'low', '2026-10-21T12:00:00Z')
            """)
            raise RuntimeError("Roll back the entire transaction")
    assert revision(client) == previous
    assert client.post("/api/events", json={}).status_code == 422
    assert revision(client) == previous
    response = client.post("/api/ingest/batch", json={
        "source": "security_event", "records": [
            {"source_ip": "192.0.2.9", "event_type": "login_success"}, {},
        ],
    })
    assert response.status_code == 200
    assert response.json()["accepted"] == 1
    assert response.json()["rejected"] == 1
    assert revision(client) > previous


def test_restart_keeps_existing_records_and_revision(client):
    alert_id = create_alert(client)
    previous = revision(client)
    initialize_database(client.app.state.database_path)
    assert revision(client) >= previous
    assert client.get(f"/api/alerts/{alert_id}").status_code == 200


@pytest.mark.parametrize("role", ["viewer", "analyst", "admin"])
def test_stream_route_all_read_roles_and_private_headers(client, monkeypatch, role):
    with database_connection(client.app.state.database_path) as connection:
        connection.execute("UPDATE users SET role = ? WHERE username = 'neehal'", (role,))

    async def finite(*args):
        yield live.sse("change", {"revision": 1})

    monkeypatch.setattr(live, "stream_changes", finite)
    response = client.get("/api/live/stream", headers={"Origin": "http://localhost:5173"})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-accel-buffering"] == "no"
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "token" not in response.text and "username" not in response.text
    assert client.app.state.live_connections.leases == {}


def test_stream_rejects_anonymous_origin_and_connection_overflow(client):
    assert client.get("/api/live/stream", headers={"Origin": "https://untrusted.example"}).status_code == 403
    for _ in range(4):
        client.app.state.live_connections.reserve(1)
    response = client.get("/api/live/stream")
    assert response.status_code == 429
    assert response.headers["retry-after"] == "5"
    client.cookies.clear()
    assert client.get("/api/live/stream").status_code == 401


def test_global_limit_and_idempotent_release():
    connections = live.LiveConnections(maximum=2, per_user=1)
    first = connections.reserve(1)
    with pytest.raises(HTTPException):
        connections.reserve(1)
    connections.reserve(2)
    with pytest.raises(HTTPException):
        connections.reserve(3)
    asyncio.run(connections.release(first))
    asyncio.run(connections.release(first))
    connections.reserve(3)


@pytest.mark.parametrize("revoke", [
    "DELETE FROM sessions",
    "UPDATE sessions SET expires_at = 0",
    "UPDATE users SET active = 0",
])
def test_open_stream_rechecks_session_and_closes(client, monkeypatch, revoke):
    monkeypatch.setattr(live, "POLL_SECONDS", 0)

    async def scenario():
        connections = live.LiveConnections()
        lease = connections.reserve(1)
        request = SimpleNamespace(is_disconnected=AsyncMock(return_value=False))
        stream = live.stream_changes(request, *identity(client), connections, lease)
        assert "retry:" in await anext(stream)
        assert "event: change" in await anext(stream)
        with database_connection(client.app.state.database_path) as connection:
            connection.execute(revoke)
        assert "event: session_expired" in await anext(stream)
        with pytest.raises(StopAsyncIteration):
            await anext(stream)
        assert connections.leases == {}
    asyncio.run(scenario())


def test_stream_heartbeat_changed_revision_reconnect_and_disconnect(client, monkeypatch):
    monkeypatch.setattr(live, "POLL_SECONDS", 0)
    monkeypatch.setattr(live, "HEARTBEAT_SECONDS", 0)

    async def scenario():
        connections = live.LiveConnections()
        request = SimpleNamespace(is_disconnected=AsyncMock(return_value=False))
        stream = live.stream_changes(request, *identity(client), connections, connections.reserve(1))
        await anext(stream)
        initial = await anext(stream)
        assert "event: heartbeat" in await anext(stream)
        assert "event: heartbeat" in await anext(stream)  # No duplicate change when idle.
        create_alert(client)
        changed = await anext(stream)
        assert "event: change" in changed and changed != initial
        await stream.aclose()
        assert connections.leases == {}
        stream = live.stream_changes(request, *identity(client), connections, connections.reserve(1))
        await anext(stream)
        assert await anext(stream) == changed  # Resync even without Last-Event-ID replay.
        request.is_disconnected.return_value = True
        await anext(stream)  # Heartbeat after the already emitted change.
        with pytest.raises(StopAsyncIteration):
            await anext(stream)
        assert connections.leases == {}
    asyncio.run(scenario())


def test_stream_database_failure_is_safe_and_releases_slot(client, monkeypatch):
    def broken(*args):
        raise sqlite3.OperationalError("private database path")
    monkeypatch.setattr(live, "live_revision", broken)

    async def scenario():
        connections = live.LiveConnections()
        stream = live.stream_changes(SimpleNamespace(is_disconnected=AsyncMock(return_value=False)),
                                     *identity(client), connections, connections.reserve(1))
        await anext(stream)
        result = await anext(stream)
        assert "event: unavailable" in result and "private" not in result
        with pytest.raises(StopAsyncIteration):
            await anext(stream)
        assert not connections.leases
    asyncio.run(scenario())
