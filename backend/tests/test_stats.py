def test_stats_reflects_full_table_not_a_capped_sample(client, analyst_headers):
    client.post("/ingest/generic", json={"logs": [
        {"timestamp": "2026-07-24T09:00:00", "host": "HOST-A", "event_type": "login_failed", "severity": "medium", "message": "m1"},
        {"timestamp": "2026-07-24T09:01:00", "host": "HOST-A", "event_type": "login_failed", "severity": "medium", "message": "m2"},
        {"timestamp": "2026-07-24T09:02:00", "host": "HOST-A", "event_type": "login_success", "severity": "low", "message": "m3"},
    ]}, headers=analyst_headers)

    response = client.get("/stats", headers=analyst_headers)
    assert response.status_code == 200
    body = response.json()

    assert body["total_events"] == 3
    assert body["severity_distribution"] == {"low": 1, "medium": 2, "high": 0, "critical": 0}
    assert body["total_incidents"] == 0
    assert body["open_incidents"] == 0
    assert body["critical_incidents"] == 0


def test_stats_incident_counts_after_correlation(client, analyst_headers):
    client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    client.post("/correlate", headers=analyst_headers)

    response = client.get("/stats", headers=analyst_headers)
    body = response.json()

    assert body["total_incidents"] == 1
    assert body["open_incidents"] == 1
    assert body["critical_incidents"] == 1
    assert len(body["recent_incidents"]) == 1
    assert body["recent_incidents"][0]["risk_level"] == "critical"


def test_stats_requires_authentication(client):
    response = client.get("/stats")
    assert response.status_code == 401
