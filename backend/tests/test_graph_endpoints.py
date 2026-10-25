from unittest.mock import patch

from neo4j.exceptions import ServiceUnavailable


def _create_incident(client, analyst_headers) -> int:
    client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    client.post("/correlate", headers=analyst_headers)
    return client.get("/incidents", headers=analyst_headers).json()["incidents"][0]["id"]


def test_sync_graph_requires_analyst_or_admin(client, analyst_headers, viewer_headers):
    with patch("app.main.resync_graph", return_value={"incidents": 0, "events_processed": 0}):
        response = client.post("/graph/sync", headers=analyst_headers)
    assert response.status_code == 200
    assert response.json() == {"incidents": 0, "events_processed": 0}

    assert client.post("/graph/sync", headers=viewer_headers).status_code == 403
    assert client.post("/graph/sync").status_code == 401


def test_sync_graph_returns_503_when_neo4j_unavailable(client, analyst_headers):
    with patch("app.main.resync_graph", side_effect=ServiceUnavailable("down")):
        response = client.post("/graph/sync", headers=analyst_headers)
    assert response.status_code == 503


def test_incident_graph_unknown_incident_returns_404(client, analyst_headers):
    response = client.get("/graph/incident/99999", headers=analyst_headers)
    assert response.status_code == 404


def test_incident_graph_returns_subgraph(client, analyst_headers):
    incident_id = _create_incident(client, analyst_headers)
    org_id = client.get("/auth/me", headers=analyst_headers).json()["organization_id"]
    fake_result = {"nodes": [{"key": "Incident:1", "label": "Incident"}], "edges": []}

    with patch("app.main.get_incident_subgraph", return_value=fake_result) as mocked:
        response = client.get(f"/graph/incident/{incident_id}", headers=analyst_headers)

    assert response.status_code == 200
    assert response.json() == fake_result
    mocked.assert_called_once_with(incident_id, org_id)


def test_incident_graph_returns_503_when_neo4j_unavailable(client, analyst_headers):
    incident_id = _create_incident(client, analyst_headers)
    with patch("app.main.get_incident_subgraph", side_effect=ServiceUnavailable("down")):
        response = client.get(f"/graph/incident/{incident_id}", headers=analyst_headers)
    assert response.status_code == 503


def test_viewer_can_view_incident_graph(client, analyst_headers, viewer_headers):
    incident_id = _create_incident(client, analyst_headers)
    with patch("app.main.get_incident_subgraph", return_value={"nodes": [], "edges": []}):
        response = client.get(f"/graph/incident/{incident_id}", headers=viewer_headers)
    assert response.status_code == 200


def test_entity_blast_radius_rejects_unknown_type(client, analyst_headers):
    response = client.get("/graph/entity", params={"type": "process", "value": "x"}, headers=analyst_headers)
    assert response.status_code == 422


def test_entity_blast_radius_returns_data(client, analyst_headers):
    org_id = client.get("/auth/me", headers=analyst_headers).json()["organization_id"]
    fake_result = {"nodes": [], "edges": []}
    with patch("app.main.get_entity_blast_radius", return_value=fake_result) as mocked:
        response = client.get(
            "/graph/entity", params={"type": "host", "value": "FINANCE-PC-21", "hops": 3}, headers=analyst_headers
        )
    assert response.status_code == 200
    mocked.assert_called_once_with("host", "FINANCE-PC-21", org_id, 3)


def test_entity_blast_radius_rejects_hops_out_of_range(client, analyst_headers):
    response = client.get("/graph/entity", params={"type": "host", "value": "x", "hops": 10}, headers=analyst_headers)
    assert response.status_code == 422


def test_full_graph_returns_data(client, analyst_headers):
    org_id = client.get("/auth/me", headers=analyst_headers).json()["organization_id"]
    fake_result = {"nodes": [], "edges": []}
    with patch("app.main.get_full_graph", return_value=fake_result) as mocked:
        response = client.get("/graph", headers=analyst_headers)
    assert response.status_code == 200
    mocked.assert_called_once_with(org_id, 300)


def test_full_graph_returns_503_when_neo4j_unavailable(client, analyst_headers):
    with patch("app.main.get_full_graph", side_effect=ServiceUnavailable("down")):
        response = client.get("/graph", headers=analyst_headers)
    assert response.status_code == 503


def test_graph_endpoints_require_authentication(client):
    assert client.get("/graph").status_code == 401
    assert client.get("/graph/incident/1").status_code == 401
    assert client.get("/graph/entity", params={"type": "host", "value": "x"}).status_code == 401
