def test_correlate_and_list_incidents(client, analyst_headers):
    client.post("/simulate/phishing_ransomware", headers=analyst_headers)

    response = client.post("/correlate", headers=analyst_headers)
    assert response.status_code == 200
    assert response.json()["incidents_created"] == 1

    listing = client.get("/incidents", headers=analyst_headers)
    assert listing.status_code == 200
    assert listing.json()["total"] == 1
    assert listing.json()["incidents"][0]["risk_level"] == "critical"


def test_incident_detail_includes_report_and_timeline(client, analyst_headers):
    client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    client.post("/correlate", headers=analyst_headers)

    incident_id = client.get("/incidents", headers=analyst_headers).json()["incidents"][0]["id"]
    detail = client.get(f"/incidents/{incident_id}", headers=analyst_headers)

    assert detail.status_code == 200
    body = detail.json()
    assert "Incident Report" in body["report"]
    assert len(body["timeline"]) == body["event_count"]


def test_unknown_incident_returns_404(client, analyst_headers):
    response = client.get("/incidents/99999", headers=analyst_headers)
    assert response.status_code == 404


def test_viewer_can_read_but_not_correlate(client, analyst_headers, viewer_headers):
    client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    client.post("/correlate", headers=analyst_headers)

    assert client.get("/incidents", headers=viewer_headers).status_code == 200
    assert client.post("/correlate", headers=viewer_headers).status_code == 403


def test_close_incident_updates_status(client, analyst_headers):
    client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    client.post("/correlate", headers=analyst_headers)
    incident_id = client.get("/incidents", headers=analyst_headers).json()["incidents"][0]["id"]

    response = client.patch(f"/incidents/{incident_id}", json={"status": "closed"}, headers=analyst_headers)
    assert response.status_code == 200
    assert response.json()["status"] == "closed"

    closed_only = client.get("/incidents", params={"status": "closed"}, headers=analyst_headers).json()
    assert closed_only["total"] == 1
