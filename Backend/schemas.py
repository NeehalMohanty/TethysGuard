from typing import Optional

from pydantic import BaseModel


class SecurityEventCreate(BaseModel):
    source_ip: str
    destination_ip: Optional[str] = None
    event_type: str
    username: Optional[str] = None
    severity: str = "low"
    message: Optional[str] = None


class SecurityEvent(SecurityEventCreate):
    id: int
    timestamp: str


class Alert(BaseModel):
    id: int
    event_id: int
    title: str
    description: str
    severity: str
    status: str
    timestamp: str


class AlertStatusUpdate(BaseModel):
    status: str


class RootResponse(BaseModel):
    name: str
    message: str
    version: str


class HealthResponse(BaseModel):
    status: str


class EventCreatedResponse(BaseModel):
    message: str
    event_id: int
    alert_created: bool
    alert_id: Optional[int] = None


class EventListResponse(BaseModel):
    count: int
    events: list[SecurityEvent]


class AlertListResponse(BaseModel):
    count: int
    alerts: list[Alert]


class AlertUpdatedResponse(BaseModel):
    message: str
    alert: Alert


class AlertStatusCounts(BaseModel):
    open: int
    investigating: int
    resolved: int


class SeverityCounts(BaseModel):
    critical: int
    high: int
    medium: int
    low: int


class DashboardStatsResponse(BaseModel):
    total_events: int
    total_alerts: int
    alert_status: AlertStatusCounts
    severity: SeverityCounts
