def create_event(client, event_type="normal_activity", severity="low"):
    return client.post(
        "/api/events",
        json={
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
            "event_type": event_type,
            "username": "analyst",
            "severity": severity,
            "message": "Automated test event",
        },
    )


def test_root_and_health(client):
    root_response = client.get("/")
    health_response = client.get("/health")

    assert root_response.status_code == 200
    assert root_response.json()["name"] == "AegisSOC"
    assert health_response.status_code == 200
    assert health_response.json() == {
        "status": "healthy",
        "database": "connected",
    }
    assert client.get("/api/dashboard/stats").json()["total_alerts"] == 0


def test_event_without_detection_is_stored(client):
    response = create_event(client)

    assert response.status_code == 200
    assert response.json()["alert_created"] is False
    assert response.json()["alert_id"] is None

    events_response = client.get("/api/events")
    assert events_response.status_code == 200
    assert events_response.json()["count"] == 1
    assert events_response.json()["events"][0]["event_type"] == "normal_activity"


def test_detected_event_creates_retrievable_alert(client):
    response = create_event(client, event_type="port_scan")

    assert response.status_code == 200
    assert response.json()["alert_created"] is True
    alert_id = response.json()["alert_id"]

    alerts_response = client.get("/api/alerts")
    alert_response = client.get(f"/api/alerts/{alert_id}")

    assert alerts_response.status_code == 200
    assert alerts_response.json()["count"] == 1
    assert alert_response.status_code == 200
    assert alert_response.json()["title"] == "Possible Port Scan"
    assert alert_response.json()["severity"] == "high"
    assert alert_response.json()["status"] == "open"


def test_alert_status_workflow(client):
    alert_id = create_event(client, event_type="malware_detected").json()["alert_id"]

    response = client.patch(
        f"/api/alerts/{alert_id}",
        json={"status": "INVESTIGATING"},
    )

    assert response.status_code == 200
    assert response.json()["alert"]["status"] == "investigating"

    invalid_response = client.patch(
        f"/api/alerts/{alert_id}",
        json={"status": "closed"},
    )
    assert invalid_response.status_code == 422


def test_missing_resources_and_invalid_payloads(client):
    assert client.get("/api/alerts/999").status_code == 404
    assert client.patch(
        "/api/alerts/999",
        json={"status": "open"},
    ).status_code == 404
    assert client.post(
        "/api/events",
        json={"event_type": "port_scan"},
    ).status_code == 422


def test_dashboard_statistics(client):
    create_event(client, event_type="normal_activity")
    create_event(client, event_type="malware_detected")
    create_event(client, event_type="failed_login")

    response = client.get("/api/dashboard/stats")

    assert response.status_code == 200
    assert response.json() == {
        "total_events": 3,
        "total_alerts": 2,
        "alert_status": {
            "open": 2,
            "investigating": 0,
            "resolved": 0,
        },
        "severity": {
            "critical": 1,
            "high": 0,
            "medium": 1,
            "low": 0,
        },
    }
