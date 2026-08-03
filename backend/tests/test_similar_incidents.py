def _make_incident(client, headers, host: str, user: str) -> None:
    client.post("/ingest/generic", json={"logs": [
        {"timestamp": "2026-07-24T09:00:00", "host": host, "username": user, "event_type": "privilege_escalation", "severity": "high", "message": f"{user} escalated privileges on {host}"},
        {"timestamp": "2026-07-24T09:01:00", "host": host, "username": user, "event_type": "process_execution", "severity": "critical", "message": f"{user} ran vssadmin delete shadows on {host}"},
    ]}, headers=headers)


def test_similar_incidents_excludes_itself_and_ranks_related_incidents(client, analyst_headers):
    _make_incident(client, analyst_headers, "HOST-A", "alice")
    _make_incident(client, analyst_headers, "HOST-B", "bob")
    client.post("/correlate", headers=analyst_headers)

    incidents = client.get("/incidents", headers=analyst_headers).json()["incidents"]
    assert len(incidents) == 2
    first_id = incidents[0]["id"]
    second_id = incidents[1]["id"]

    response = client.get(f"/incidents/{first_id}/similar", headers=analyst_headers)
    assert response.status_code == 200
    body = response.json()

    assert body["incident_id"] == first_id
    matched_ids = [m["id"] for m in body["matches"]]
    assert first_id not in matched_ids
    assert second_id in matched_ids
    assert "similarity" in body["matches"][0]


def test_similar_incidents_unknown_id_returns_404(client, analyst_headers):
    response = client.get("/incidents/99999/similar", headers=analyst_headers)
    assert response.status_code == 404


def test_similar_incidents_requires_authentication(client):
    response = client.get("/incidents/1/similar")
    assert response.status_code == 401
