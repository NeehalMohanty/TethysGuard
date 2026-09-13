from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from typing import Any

from Backend.database import database_connection
from Backend.config import settings
from Backend.detection import DetectionContext, analyze_event
from Backend.schemas import AlertStatus, SecurityEventCreate, Severity


EVENT_SORT_COLUMNS = {
    "id": "id",
    "timestamp": "timestamp",
    "severity": (
        "CASE severity "
        "WHEN 'low' THEN 1 "
        "WHEN 'medium' THEN 2 "
        "WHEN 'high' THEN 3 "
        "WHEN 'critical' THEN 4 END"
    ),
    "event_type": "event_type",
}
ALERT_SORT_COLUMNS = {
    "id": "id",
    "timestamp": "timestamp",
    "severity": (
        "CASE severity "
        "WHEN 'low' THEN 1 "
        "WHEN 'medium' THEN 2 "
        "WHEN 'high' THEN 3 "
        "WHEN 'critical' THEN 4 END"
    ),
    "status": "status",
    "title": "title",
}


def _utc_iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _like_pattern(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _alert_from_row(row: Any) -> dict[str, Any]:
    alert = dict(row)
    serialized_evidence = alert.get("evidence")
    if serialized_evidence:
        try:
            alert["evidence"] = json.loads(serialized_evidence)
        except (TypeError, json.JSONDecodeError):
            alert["evidence"] = {"legacy_value": str(serialized_evidence)}
    else:
        alert["evidence"] = None
    return alert


def _failed_login_count(
    connection: Any,
    event: SecurityEventCreate,
    timestamp: datetime,
) -> int:
    if event.event_type != "failed_login":
        return 0

    window_start = timestamp - timedelta(
        minutes=settings.failed_login_window_minutes
    )
    username = event.username
    return int(
        connection.execute(
            """
            SELECT COUNT(*) FROM events
            WHERE event_type = 'failed_login'
                AND timestamp >= ?
                AND timestamp <= ?
                AND (source_ip = ? OR (? IS NOT NULL AND username = ?))
            """,
            (
                window_start.isoformat(),
                timestamp.isoformat(),
                str(event.source_ip),
                username,
                username,
            ),
        ).fetchone()[0]
    )


def create_security_event(
    event: SecurityEventCreate,
    database_path: Path | str,
) -> dict[str, Any]:
    event_time = datetime.now(timezone.utc)
    timestamp = event_time.isoformat()

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
                str(event.source_ip),
                str(event.destination_ip) if event.destination_ip else None,
                event.event_type,
                event.username,
                event.severity.value,
                event.message,
                timestamp,
            ),
        )
        event_id = int(cursor.lastrowid)
        detection_context = DetectionContext(
            failed_login_count=_failed_login_count(connection, event, event_time),
            failed_login_threshold=settings.failed_login_threshold,
            failed_login_window_minutes=settings.failed_login_window_minutes,
            detected_at=event_time,
        )
        detected_alerts = analyze_event(event, detection_context)
        alert_ids: list[int] = []

        for detected_alert in detected_alerts:
            alert_cursor = connection.execute(
                """
                INSERT INTO alerts (
                    event_id,
                    title,
                    description,
                    severity,
                    status,
                    timestamp,
                    rule_id,
                    rule_name,
                    category,
                    confidence,
                    risk_score,
                    evidence,
                    mitre_tactic,
                    mitre_technique_id,
                    mitre_technique_name,
                    detected_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    detected_alert["title"],
                    detected_alert["description"],
                    detected_alert["severity"],
                    AlertStatus.OPEN.value,
                    timestamp,
                    detected_alert["rule_id"],
                    detected_alert["rule_name"],
                    detected_alert["category"],
                    detected_alert["confidence"],
                    detected_alert["risk_score"],
                    json.dumps(detected_alert["evidence"], sort_keys=True),
                    detected_alert["mitre_tactic"],
                    detected_alert["mitre_technique_id"],
                    detected_alert["mitre_technique_name"],
                    detected_alert["detected_at"],
                ),
            )
            alert_ids.append(int(alert_cursor.lastrowid))

    return {
        "message": "Security event processed",
        "event_id": event_id,
        "alert_created": bool(alert_ids),
        "alert_id": alert_ids[0] if alert_ids else None,
        "alerts_created": len(alert_ids),
        "alert_ids": alert_ids,
    }


def list_events(
    database_path: Path | str,
    *,
    limit: int,
    offset: int,
    severity: Severity | None = None,
    event_type: str | None = None,
    source_ip: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    search: str | None = None,
    sort_by: str = "id",
    sort_order: str = "desc",
) -> tuple[int, list[dict[str, Any]]]:
    filters: list[str] = []
    parameters: list[Any] = []

    if severity is not None:
        filters.append("severity = ?")
        parameters.append(severity.value)
    if event_type is not None:
        filters.append("event_type = ?")
        parameters.append(event_type)
    if source_ip is not None:
        filters.append("source_ip = ?")
        parameters.append(source_ip)
    if start_time is not None:
        filters.append("timestamp >= ?")
        parameters.append(_utc_iso(start_time))
    if end_time is not None:
        filters.append("timestamp <= ?")
        parameters.append(_utc_iso(end_time))
    if search is not None:
        filters.append(
            """
            (source_ip LIKE ? ESCAPE '\\'
                OR COALESCE(destination_ip, '') LIKE ? ESCAPE '\\'
                OR event_type LIKE ? ESCAPE '\\'
                OR COALESCE(username, '') LIKE ? ESCAPE '\\'
                OR COALESCE(message, '') LIKE ? ESCAPE '\\')
            """
        )
        pattern = _like_pattern(search)
        parameters.extend([pattern] * 5)

    where_clause = f"WHERE {' AND '.join(filters)}" if filters else ""
    sort_column = EVENT_SORT_COLUMNS[sort_by]
    direction = "ASC" if sort_order == "asc" else "DESC"

    with database_connection(database_path) as connection:
        total = connection.execute(
            f"SELECT COUNT(*) FROM events {where_clause}",
            parameters,
        ).fetchone()[0]
        rows = connection.execute(
            f"""
            SELECT * FROM events
            {where_clause}
            ORDER BY {sort_column} {direction}, id {direction}
            LIMIT ? OFFSET ?
            """,
            [*parameters, limit, offset],
        ).fetchall()

    return total, [dict(row) for row in rows]


def list_alerts(
    database_path: Path | str,
    *,
    limit: int,
    offset: int,
    alert_status: AlertStatus | None = None,
    severity: Severity | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    search: str | None = None,
    sort_by: str = "id",
    sort_order: str = "desc",
) -> tuple[int, list[dict[str, Any]]]:
    filters: list[str] = []
    parameters: list[Any] = []

    if alert_status is not None:
        filters.append("status = ?")
        parameters.append(alert_status.value)
    if severity is not None:
        filters.append("severity = ?")
        parameters.append(severity.value)
    if start_time is not None:
        filters.append("timestamp >= ?")
        parameters.append(_utc_iso(start_time))
    if end_time is not None:
        filters.append("timestamp <= ?")
        parameters.append(_utc_iso(end_time))
    if search is not None:
        filters.append(
            "(title LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\')"
        )
        pattern = _like_pattern(search)
        parameters.extend([pattern, pattern])

    where_clause = f"WHERE {' AND '.join(filters)}" if filters else ""
    sort_column = ALERT_SORT_COLUMNS[sort_by]
    direction = "ASC" if sort_order == "asc" else "DESC"

    with database_connection(database_path) as connection:
        total = connection.execute(
            f"SELECT COUNT(*) FROM alerts {where_clause}",
            parameters,
        ).fetchone()[0]
        rows = connection.execute(
            f"""
            SELECT * FROM alerts
            {where_clause}
            ORDER BY {sort_column} {direction}, id {direction}
            LIMIT ? OFFSET ?
            """,
            [*parameters, limit, offset],
        ).fetchall()

    return total, [_alert_from_row(row) for row in rows]


def get_alert_by_id(
    alert_id: int,
    database_path: Path | str,
) -> dict[str, Any] | None:
    with database_connection(database_path) as connection:
        row = connection.execute(
            "SELECT * FROM alerts WHERE id = ?",
            (alert_id,),
        ).fetchone()
    return _alert_from_row(row) if row is not None else None


def update_alert_status(
    alert_id: int,
    new_status: AlertStatus,
    database_path: Path | str,
) -> dict[str, Any] | None:
    changed_at = datetime.now(timezone.utc).isoformat()

    with database_connection(database_path) as connection:
        existing_alert = connection.execute(
            "SELECT id, status FROM alerts WHERE id = ?",
            (alert_id,),
        ).fetchone()
        if existing_alert is None:
            return None

        previous_status = existing_alert["status"]
        if previous_status != new_status.value:
            connection.execute(
                "UPDATE alerts SET status = ? WHERE id = ?",
                (new_status.value, alert_id),
            )
            connection.execute(
                """
                INSERT INTO alert_status_history (
                    alert_id,
                    previous_status,
                    new_status,
                    changed_at
                )
                VALUES (?, ?, ?, ?)
                """,
                (alert_id, previous_status, new_status.value, changed_at),
            )

        updated_alert = connection.execute(
            "SELECT * FROM alerts WHERE id = ?",
            (alert_id,),
        ).fetchone()

    return _alert_from_row(updated_alert)


def list_alert_history(
    alert_id: int,
    database_path: Path | str,
) -> list[dict[str, Any]] | None:
    with database_connection(database_path) as connection:
        alert_exists = connection.execute(
            "SELECT id FROM alerts WHERE id = ?",
            (alert_id,),
        ).fetchone()
        if alert_exists is None:
            return None

        rows = connection.execute(
            """
            SELECT * FROM alert_status_history
            WHERE alert_id = ?
            ORDER BY id DESC
            """,
            (alert_id,),
        ).fetchall()

    return [dict(row) for row in rows]


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
