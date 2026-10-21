"""Bounded SSE invalidation stream, backed by committed SQLite revisions."""
import asyncio
import json
import logging
from pathlib import Path
import secrets
import sqlite3
import time

from fastapi import APIRouter, HTTPException, Request
from starlette.background import BackgroundTask
from starlette.concurrency import run_in_threadpool
from starlette.responses import StreamingResponse

from Backend.auth import CurrentUser, check_origin
from Backend.database import database_connection

POLL_SECONDS = 2
HEARTBEAT_SECONDS = 15
logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/live", tags=["live updates"])


class LiveConnections:
    """Per-process limits. Reserve/release run on the application's event loop."""
    def __init__(self, maximum=32, per_user=4):
        self.maximum = maximum
        self.per_user = per_user
        self.leases: dict[str, int] = {}

    def reserve(self, user_id: int) -> str:
        if len(self.leases) >= self.maximum or list(self.leases.values()).count(user_id) >= self.per_user:
            raise HTTPException(429, "Too many live connections; close another tab and retry",
                                headers={"Retry-After": "5"})
        lease = secrets.token_hex(16)
        self.leases[lease] = user_id
        return lease

    async def release(self, lease: str):
        self.leases.pop(lease, None)


def live_revision(path: Path | str, token_hash: str) -> int | None:
    # Reauthorize on every sample, not just when the HTTP connection opens.
    with database_connection(path) as connection:
        connection.execute("BEGIN")
        valid = connection.execute("""
            SELECT 1 FROM sessions s JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = ? AND s.expires_at > ? AND u.active = 1
        """, (token_hash, int(time.time()))).fetchone()
        if valid is None:
            return None
        return connection.execute("SELECT revision FROM live_revision WHERE id = 1").fetchone()[0]


def sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


async def stream_changes(request, path, token_hash, connections, lease):
    previous = None
    heartbeat_at = time.monotonic() + HEARTBEAT_SECONDS
    try:
        yield "retry: 5000\n\n"
        while not await request.is_disconnected():
            try:
                revision = await run_in_threadpool(live_revision, path, token_hash)
            except sqlite3.Error:
                logger.warning("Live update database read failed")
                yield sse("unavailable", {})
                return
            if revision is None:
                yield sse("session_expired", {})
                return
            if revision != previous:
                # Initial connection/reconnection always resynchronizes REST data.
                # No replay queue or sensitive record payload travels over SSE.
                yield sse("change", {"revision": revision})
                previous = revision
            if time.monotonic() >= heartbeat_at:
                yield sse("heartbeat", {})
                heartbeat_at = time.monotonic() + HEARTBEAT_SECONDS
            await asyncio.sleep(POLL_SECONDS)
    finally:
        await connections.release(lease)


@router.get("/stream")
async def live_stream(request: Request, user: CurrentUser):
    check_origin(request)
    connections = request.app.state.live_connections
    lease = connections.reserve(user["id"])
    return StreamingResponse(
        stream_changes(request, request.app.state.database_path, user["token_hash"], connections, lease),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        background=BackgroundTask(connections.release, lease),
    )
