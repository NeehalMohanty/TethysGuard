import os
from dataclasses import dataclass
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parent


def _environment(name: str, default: str) -> str:
    """Prefer the current prefix while accepting existing local configuration."""
    legacy_name = name.replace("TETHYSGUARD_", "AEGISSOC_", 1)
    return os.getenv(name, os.getenv(legacy_name, default))


def _default_database_path() -> Path:
    current = BACKEND_DIR / "tethysguard.db"
    legacy = BACKEND_DIR / "aegissoc.db"
    return legacy if legacy.exists() and not current.exists() else current


def _get_cors_origins() -> tuple[str, ...]:
    configured_origins = _environment(
        "TETHYSGUARD_CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    )
    return tuple(
        origin.strip()
        for origin in configured_origins.split(",")
        if origin.strip()
    )


@dataclass(frozen=True)
class Settings:
    app_name: str = _environment("TETHYSGUARD_APP_NAME", "TethysGuard API")
    app_version: str = _environment("TETHYSGUARD_APP_VERSION", "0.3.0")
    app_description: str = "Cybersecurity monitoring and threat detection platform"
    database_path: Path = Path(
        _environment("TETHYSGUARD_DATABASE_PATH", str(_default_database_path()))
    )
    cors_origins: tuple[str, ...] = _get_cors_origins()
    max_request_body_bytes: int = int(
        _environment("TETHYSGUARD_MAX_REQUEST_BODY_BYTES", "16384")
    )


settings = Settings()
