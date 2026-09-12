from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Query, Request, status
from pydantic import IPvAnyAddress

from Backend.schemas import (
    EventCreatedResponse,
    EventListResponse,
    SecurityEventCreate,
    Severity,
)
from Backend.services import create_security_event, list_events
from Backend.routes.utils import validate_date_range


router = APIRouter(prefix="/api/events", tags=["events"])


@router.post("", response_model=EventCreatedResponse, status_code=status.HTTP_200_OK)
def create_event(
    event: SecurityEventCreate,
    request: Request,
) -> dict[str, Any]:
    return create_security_event(event, request.app.state.database_path)


@router.get("", response_model=EventListResponse)
def get_events(
    request: Request,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    severity: Severity | None = None,
    event_type: Annotated[
        str | None,
        Query(min_length=1, max_length=100, pattern=r"^[a-zA-Z0-9_.:-]+$"),
    ] = None,
    source_ip: IPvAnyAddress | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    search: Annotated[str | None, Query(min_length=1, max_length=100)] = None,
    sort_by: Literal["id", "timestamp", "severity", "event_type"] = "id",
    sort_order: Literal["asc", "desc"] = "desc",
) -> dict[str, Any]:
    validate_date_range(start_time, end_time)

    normalized_event_type = event_type.strip().lower() if event_type else None
    normalized_search = search.strip() if search else None
    total, events = list_events(
        request.app.state.database_path,
        limit=limit,
        offset=offset,
        severity=severity,
        event_type=normalized_event_type,
        source_ip=str(source_ip) if source_ip else None,
        start_time=start_time,
        end_time=end_time,
        search=normalized_search,
        sort_by=sort_by,
        sort_order=sort_order,
    )
    return {
        "count": len(events),
        "total": total,
        "limit": limit,
        "offset": offset,
        "events": events,
    }
