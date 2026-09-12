from typing import Any

from fastapi import APIRouter, Request

from Backend.schemas import DashboardStatsResponse
from Backend.services import get_dashboard_stats


router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/stats", response_model=DashboardStatsResponse)
def dashboard_stats(request: Request) -> dict[str, Any]:
    return get_dashboard_stats(request.app.state.database_path)
