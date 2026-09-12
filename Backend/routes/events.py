from typing import Any

from fastapi import APIRouter, Request, status

from Backend.schemas import (
    EventCreatedResponse,
    EventListResponse,
    SecurityEventCreate,
)
from Backend.services import create_security_event, list_events


router = APIRouter(prefix="/api/events", tags=["events"])


@router.post("", response_model=EventCreatedResponse, status_code=status.HTTP_200_OK)
def create_event(
    event: SecurityEventCreate,
    request: Request,
) -> dict[str, Any]:
    return create_security_event(event, request.app.state.database_path)


@router.get("", response_model=EventListResponse)
def get_events(request: Request) -> dict[str, Any]:
    events = list_events(request.app.state.database_path)
    return {"count": len(events), "events": events}
