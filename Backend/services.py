from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from Backend.database import database_connection
from Backend.detection import analyze_event
from Backend.schemas import SecurityEventCreate


ALLOWED_ALERT_STATUSES = {"open", "investigating", "resolved"}


def create_security_event(
    event: SecurityEventCreate,
    database_path: Path | str,
) -> dict[str, Any]:
    timestamp = datetime.now(timezone.utc).isoformat()

    with database_connection(database_path) as connection:
        cursor = connection.execute(
            """
            INSERT INTO events (
                source_ip,
                destination_ip,
                event_type,
                username,
                severity,
                message,
                timestamp
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.source_ip,
                event.destination_ip,
                event.event_type,
                event.username,
                event.severity.lower(),
                event.message,
                timestamp,
            ),
        )
        event_id = int(cursor.lastrowid)
        detected_alert = analyze_event(event)
        alert_id = None

        if detected_alert:
            alert_cursor = connection.execute(
                """
                INSERT INTO alerts (
                    event_id,
                    title,
                    description,
                    severity,
                    status,
                    timestamp
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    detected_alert["title"],
                    detected_alert["description"],
                    detected_alert["severity"],
                    "open",
                    timestamp,
                ),
            )
            alert_id = int(alert_cursor.lastrowid)

    return {
        "message": "Security event processed",
        "event_id": event_id,
        "alert_created": alert_id is not None,
        "alert_id": alert_id,
    }


def list_events(database_path: Path | str) -> list[dict[str, Any]]:
    with database_connection(database_path) as connection:
        rows = connection.execute(
            "SELECT * FROM events ORDER BY id DESC"
        ).fetchall()
    return [dict(row) for row in rows]


def list_alerts(database_path: Path | str) -> list[dict[str, Any]]:
    with database_connection(database_path) as connection:
        rows = connection.execute(
            "SELECT * FROM alerts ORDER BY id DESC"
        ).fetchall()
    return [dict(row) for row in rows]


def get_alert_by_id(
    alert_id: int,
    database_path: Path | str,
) -> dict[str, Any] | None:
    with database_connection(database_path) as connection:
        row = connection.execute(
            "SELECT * FROM alerts WHERE id = ?",
            (alert_id,),
        ).fetchone()
    return dict(row) if row is not None else None


def update_alert_status(
    alert_id: int,
    status: str,
    database_path: Path | str,
) -> dict[str, Any] | None:
    with database_connection(database_path) as connection:
        existing_alert = connection.execute(
            "SELECT id FROM alerts WHERE id = ?",
            (alert_id,),
        ).fetchone()
        if existing_alert is None:
            return None

        connection.execute(
            "UPDATE alerts SET status = ? WHERE id = ?",
            (status, alert_id),
        )
        updated_alert = connection.execute(
            "SELECT * FROM alerts WHERE id = ?",
            (alert_id,),
        ).fetchone()

    return dict(updated_alert)


def get_dashboard_stats(database_path: Path | str) -> dict[str, Any]:
    with database_connection(database_path) as connection:
        total_events = connection.execute(
            "SELECT COUNT(*) FROM events"
        ).fetchone()[0]
        alert_counts = connection.execute(
            """
            SELECT
                COUNT(*) AS total,
                COALESCE(SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END), 0)
                    AS open,
                COALESCE(SUM(CASE WHEN status = 'investigating' THEN 1 ELSE 0 END), 0)
                    AS investigating,
                COALESCE(SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END), 0)
                    AS resolved,
                COALESCE(SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END), 0)
                    AS critical,
                COALESCE(SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END), 0)
                    AS high,
                COALESCE(SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END), 0)
                    AS medium,
                COALESCE(SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END), 0)
                    AS low
            FROM alerts
            """
        ).fetchone()

    return {
        "total_events": total_events,
        "total_alerts": alert_counts["total"],
        "alert_status": {
            "open": alert_counts["open"],
            "investigating": alert_counts["investigating"],
            "resolved": alert_counts["resolved"],
        },
        "severity": {
            "critical": alert_counts["critical"],
            "high": alert_counts["high"],
            "medium": alert_counts["medium"],
            "low": alert_counts["low"],
        },
    }
