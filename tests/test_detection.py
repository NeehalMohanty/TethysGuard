import pytest

from Backend.detection import analyze_event
from Backend.schemas import SecurityEventCreate


@pytest.mark.parametrize(
    ("event_type", "severity", "expected_title", "expected_severity"),
    [
        ("malware_detected", "low", "Malware Detected", "critical"),
        ("port_scan", "low", "Possible Port Scan", "high"),
        (
            "unauthorized_access",
            "low",
            "Unauthorized Access Attempt",
            "high",
        ),
        ("failed_login", "low", "Failed Login Attempt", "medium"),
        ("unknown_event", "critical", "Critical Security Event", "critical"),
    ],
)
def test_existing_detection_rules(
    event_type,
    severity,
    expected_title,
    expected_severity,
):
    event = SecurityEventCreate(
        source_ip="192.0.2.10",
        event_type=event_type,
        username="analyst",
        severity=severity,
    )

    alert = analyze_event(event)

    assert alert is not None
    assert alert["title"] == expected_title
    assert alert["severity"] == expected_severity


def test_benign_event_does_not_create_detection():
    event = SecurityEventCreate(
        source_ip="192.0.2.10",
        event_type="normal_activity",
    )

    assert analyze_event(event) is None
