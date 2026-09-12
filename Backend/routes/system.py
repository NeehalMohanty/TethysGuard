from fastapi import APIRouter

from Backend.config import settings
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
def health() -> dict[str, str]:
    return {"status": "healthy"}
