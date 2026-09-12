from typing import Any

from fastapi import APIRouter, HTTPException, Request, status

from Backend.schemas import (
    Alert,
    AlertListResponse,
    AlertStatusUpdate,
    AlertUpdatedResponse,
)
from Backend.services import (
    ALLOWED_ALERT_STATUSES,
    get_alert_by_id,
    list_alerts,
    update_alert_status,
)


router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("", response_model=AlertListResponse)
def get_alerts(request: Request) -> dict[str, Any]:
    alerts = list_alerts(request.app.state.database_path)
    return {"count": len(alerts), "alerts": alerts}


@router.get("/{alert_id}", response_model=Alert)
def get_alert(alert_id: int, request: Request) -> dict[str, Any]:
    alert = get_alert_by_id(alert_id, request.app.state.database_path)
    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )
    return alert


@router.patch("/{alert_id}", response_model=AlertUpdatedResponse)
def patch_alert_status(
    alert_id: int,
    update: AlertStatusUpdate,
    request: Request,
) -> dict[str, Any]:
    new_status = update.status.lower()
    if new_status not in ALLOWED_ALERT_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Invalid status. "
                "Allowed values: open, investigating, resolved"
            ),
        )

    alert = update_alert_status(
        alert_id,
        new_status,
        request.app.state.database_path,
    )
    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )

    return {
        "message": "Alert status updated successfully",
        "alert": alert,
    }
