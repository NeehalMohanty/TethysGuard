import os
from dataclasses import dataclass
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parent


def _get_cors_origins() -> tuple[str, ...]:
    configured_origins = os.getenv(
        "AEGISSOC_CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    )
    return tuple(
        origin.strip()
        for origin in configured_origins.split(",")
        if origin.strip()
    )


@dataclass(frozen=True)
class Settings:
    app_name: str = os.getenv("AEGISSOC_APP_NAME", "AegisSOC API")
    app_version: str = os.getenv("AEGISSOC_APP_VERSION", "0.3.0")
    app_description: str = "Cybersecurity monitoring and threat detection platform"
    database_path: Path = Path(
        os.getenv("AEGISSOC_DATABASE_PATH", str(BACKEND_DIR / "aegissoc.db"))
    )
    cors_origins: tuple[str, ...] = _get_cors_origins()


settings = Settings()
