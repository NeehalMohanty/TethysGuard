"""Analyst workflow storage. HTTP callers supply identity from authenticated sessions."""
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any

from Backend.database import database_connection


def record_activity(
    connection: sqlite3.Connection,
    alert_id: int,
    action: str,
    actor: str,
    details: dict[str, Any],
    created_at: str,
    status_history_id: int | None = None,
    actor_user_id: int | None = None,
) -> dict[str, Any]:
    cursor = connection.execute("""
        INSERT INTO alert_activity
            (alert_id, action, actor, details, created_at, status_history_id, actor_user_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (alert_id, action, actor, json.dumps(details), created_at, status_history_id, actor_user_id))
    return {"id": cursor.lastrowid, "alert_id": alert_id, "action": action,
            "actor": actor, "actor_user_id": actor_user_id, "details": details, "created_at": created_at}


def assign_alert(
    alert_id: int,
    assigned_to: str | None,
    actor: str,
    database_path: Path | str,
    *,
    actor_user_id: int | None = None,
) -> bool:
    with database_connection(database_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute("SELECT assigned_to FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if row is None:
            return False
        if assigned_to is not None:
            account = connection.execute("""
                SELECT username FROM users WHERE username = ? AND active = 1
                AND role IN ('admin', 'analyst')
            """, (assigned_to,)).fetchone()
            if account is None:
                raise ValueError("Assign an active analyst or admin account")
            assigned_to = account["username"]
        if row["assigned_to"] != assigned_to:
            connection.execute("UPDATE alerts SET assigned_to = ? WHERE id = ?", (assigned_to, alert_id))
            record_activity(connection, alert_id, "assigned", actor,
                            {"previous_assignee": row["assigned_to"], "assigned_to": assigned_to},
                            datetime.now(timezone.utc).isoformat(), actor_user_id=actor_user_id)
    return True


def add_note(
    alert_id: int,
    body: str,
    actor: str,
    database_path: Path | str,
    *,
    actor_user_id: int | None = None,
) -> dict[str, Any] | None:
    with database_connection(database_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        if connection.execute("SELECT id FROM alerts WHERE id = ?", (alert_id,)).fetchone() is None:
            return None
        # Notes are append-only activity records: the note and its audit entry are one row.
        return record_activity(connection, alert_id, "note_added", actor, {"body": body},
                               datetime.now(timezone.utc).isoformat(), actor_user_id=actor_user_id)


def list_timeline(
    alert_id: int,
    database_path: Path | str,
    *,
    limit: int,
    offset: int,
) -> dict[str, Any] | None:
    with database_connection(database_path) as connection:
        connection.execute("BEGIN")
        alert = connection.execute("SELECT timestamp FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if alert is None:
            return None
        total = 1 + connection.execute(
            "SELECT COUNT(*) FROM alert_activity WHERE alert_id = ?", (alert_id,)
        ).fetchone()[0]
        rows = connection.execute("""
            SELECT id, alert_id, action, actor, details, created_at, actor_user_id
            FROM alert_activity WHERE alert_id = ?
            UNION ALL
            SELECT 0, ?, 'created', 'Detection engine', '{}', ?, NULL
            ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?
        """, (alert_id, alert_id, alert["timestamp"], limit, offset)).fetchall()
        activities = [{**dict(row), "details": json.loads(row["details"])} for row in rows]
    return {"count": len(activities), "total": total, "limit": limit,
            "offset": offset, "activities": activities}
