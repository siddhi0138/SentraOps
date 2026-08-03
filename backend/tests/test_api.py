def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_ingest_generic_logs_via_api(client, analyst_headers):
    response = client.post("/ingest/generic", json={"logs": [{
        "timestamp": "2026-07-24T09:16:52",
        "host": "FINANCE-PC-21",
        "user": "j.mehta",
        "event_type": "login_failed",
        "detail": "Failed login attempt",
        "source_ip": "185.220.101.45",
    }]}, headers=analyst_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["ingested"] == 1
    assert body["events"][0]["event_type"] == "login_failed"


def test_ingest_unknown_source_type_returns_400(client, analyst_headers):
    response = client.post("/ingest/not_a_real_source", json={"logs": []}, headers=analyst_headers)
    assert response.status_code == 400


def test_ingest_requires_authentication(client):
    response = client.post("/ingest/generic", json={"logs": []})
    assert response.status_code == 401  # no Authorization header at all


def test_viewer_cannot_ingest(client, viewer_headers):
    response = client.post("/ingest/generic", json={"logs": []}, headers=viewer_headers)
    assert response.status_code == 403


def test_simulate_ingests_multi_source_scenario_and_is_searchable(client, analyst_headers):
    response = client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["mode"] == "synthetic"  # no real cluster access in tests (see conftest.py)
    sources = body["sources"]
    assert sources["windows"]["ingested"] > 0
    assert sources["firewall"]["ingested"] > 0
    assert sources["syslog"]["ingested"] > 0

    critical = client.get("/events", params={"severity": "critical"}, headers=analyst_headers).json()
    assert critical["total"] >= 1

    search = client.get("/events", params={"q": "185.220.101.45"}, headers=analyst_headers).json()
    assert search["total"] >= 1


def test_simulate_uses_real_bas_campaign_when_cluster_available(client, analyst_headers):
    from unittest.mock import patch

    fake_event = {
        "timestamp": "2026-07-31T00:00:00+00:00", "host": "sentraops-bas-target-1", "username": "bas-simulation",
        "event_type": "bas_t1082", "severity": "low", "message": "[BAS] T1082 System Information Discovery - exit 0: Linux",
    }
    with patch("app.main.bas.run_campaign", return_value=[fake_event]):
        response = client.post("/simulate/phishing_ransomware", headers=analyst_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["mode"] == "real"
    assert body["sources"]["bas"]["ingested"] == 1


def test_simulate_unknown_scenario_400s_regardless_of_cluster_availability(client, analyst_headers):
    response = client.post("/simulate/not-a-real-scenario", headers=analyst_headers)
    assert response.status_code == 400


def test_viewer_can_read_events(client, analyst_headers, viewer_headers):
    client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    response = client.get("/events", headers=viewer_headers)
    assert response.status_code == 200
    assert response.json()["total"] > 0
