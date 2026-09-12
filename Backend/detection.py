from typing import TypedDict

from Backend.schemas import SecurityEventCreate


class DetectedAlert(TypedDict):
    title: str
    description: str
    severity: str


def analyze_event(event: SecurityEventCreate) -> DetectedAlert | None:

    event_type = event.event_type.lower()
    severity = event.severity.lower()

    alert: DetectedAlert | None = None

    if event_type == "malware_detected":

        alert = {
            "title": "Malware Detected",
            "description": (
                f"Malware activity detected from {event.source_ip}"
            ),
            "severity": "critical"
        }

    elif event_type == "port_scan":

        alert = {
            "title": "Possible Port Scan",
            "description": (
                f"Port scanning activity detected from "
                f"{event.source_ip}"
            ),
            "severity": "high"
        }

    elif event_type == "unauthorized_access":

        alert = {
            "title": "Unauthorized Access Attempt",
            "description": (
                f"Unauthorized access attempt from "
                f"{event.source_ip}"
            ),
            "severity": "high"
        }

    elif event_type == "failed_login":

        alert = {
            "title": "Failed Login Attempt",
            "description": (
                f"Failed login attempt detected for "
                f"user {event.username}"
            ),
            "severity": "medium"
        }

    elif severity == "critical":

        alert = {
            "title": "Critical Security Event",
            "description": (
                f"Critical security event detected from "
                f"{event.source_ip}"
            ),
            "severity": "critical"
        }

    return alert
