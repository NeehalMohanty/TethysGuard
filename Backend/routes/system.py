from fastapi import APIRouter, HTTPException, Request, status

from Backend.config import settings
from Backend.database import database_is_available
from Backend.schemas import HealthResponse, RootResponse


router = APIRouter(tags=["system"])


@router.get("/", response_model=RootResponse)
def root() -> dict[str, str]:
    return {
        "name": "AegisSOC",
        "message": "AegisSOC API is running",
        "version": settings.app_version,
    }


@router.get("/health", response_model=HealthResponse)
def health(request: Request) -> dict[str, str]:
    if not database_is_available(request.app.state.database_path):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database is unavailable",
        )
    return {"status": "healthy", "database": "connected"}
