from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"


class APIModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class SecurityEventCreate(APIModel):
    source_ip: IPvAnyAddress
    destination_ip: Optional[IPvAnyAddress] = None
    event_type: str = Field(min_length=1, max_length=100, pattern=r"^[a-z0-9_.:-]+$")
    username: Optional[str] = Field(default=None, max_length=255)
    severity: Severity = Severity.LOW
    message: Optional[str] = Field(default=None, max_length=2000)

    @field_validator("event_type", mode="before")
    @classmethod
    def normalize_event_type(cls, value: Any) -> Any:
        return value.strip().lower() if isinstance(value, str) else value

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, value: Any) -> Any:
        return value.strip().lower() if isinstance(value, str) else value

    @field_validator("username", "message", mode="before")
    @classmethod
    def normalize_optional_text(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        normalized = value.strip()
        return normalized or None


class SecurityEvent(SecurityEventCreate):
    id: int
    timestamp: str


class Alert(APIModel):
    id: int
    event_id: int
    title: str
    description: str
    severity: Severity
    status: AlertStatus
    timestamp: str


class AlertStatusUpdate(APIModel):
    status: AlertStatus

    @field_validator("status", mode="before")
    @classmethod
    def normalize_status(cls, value: Any) -> Any:
        return value.strip().lower() if isinstance(value, str) else value


class AlertStatusHistory(APIModel):
    id: int
    alert_id: int
    previous_status: AlertStatus
    new_status: AlertStatus
    changed_at: str


class RootResponse(APIModel):
    name: str
    message: str
    version: str


class HealthResponse(APIModel):
    status: str
    database: str


class EventCreatedResponse(APIModel):
    message: str
    event_id: int
    alert_created: bool
    alert_id: Optional[int] = None


class EventListResponse(APIModel):
    count: int
    total: int
    limit: int
    offset: int
    events: list[SecurityEvent]


class AlertListResponse(APIModel):
    count: int
    total: int
    limit: int
    offset: int
    alerts: list[Alert]


class AlertHistoryListResponse(APIModel):
    count: int
    history: list[AlertStatusHistory]


class AlertUpdatedResponse(APIModel):
    message: str
    alert: Alert


class AlertStatusCounts(APIModel):
    open: int
    investigating: int
    resolved: int


class SeverityCounts(APIModel):
    critical: int
    high: int
    medium: int
    low: int


class DashboardStatsResponse(APIModel):
    total_events: int
    total_alerts: int
    alert_status: AlertStatusCounts
    severity: SeverityCounts
