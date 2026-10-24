from unittest.mock import patch

import pytest


@pytest.fixture
def seeded(client, analyst_headers):
    client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    client.post("/correlate", headers=analyst_headers)
    incident_id = client.get("/incidents", headers=analyst_headers).json()["incidents"][0]["id"]
    return incident_id


@pytest.fixture
def neo4j_deleted():
    # What a deleted Aura instance raises when the app tries to connect.
    with patch("app.graph.get_driver", side_effect=ValueError("Cannot resolve address x.databases.neo4j.io:7687")):
        yield


def test_full_graph_is_served_from_postgres_when_neo4j_is_deleted(client, analyst_headers, seeded, neo4j_deleted):
    response = client.get("/graph", headers=analyst_headers)
    assert response.status_code == 200
    graph = response.json()
    labels = {n["label"] for n in graph["nodes"]}
    assert {"Incident", "Host"} <= labels
    types = {e["type"] for e in graph["edges"]}
    assert "PART_OF" in types
    keys = {n["key"] for n in graph["nodes"]}
    assert all(e["from"] in keys and e["to"] in keys for e in graph["edges"])
    assert "org_key" not in graph["nodes"][0]


def test_incident_subgraph_matches_the_incident_it_was_asked_for(client, analyst_headers, seeded, neo4j_deleted):
    response = client.get(f"/graph/incident/{seeded}", headers=analyst_headers)
    assert response.status_code == 200
    graph = response.json()
    assert any(n["label"] == "Incident" and n["id"] == seeded for n in graph["nodes"])
    assert graph["edges"]


def test_blast_radius_is_case_insensitive_and_unknown_entities_are_empty(client, analyst_headers, seeded, neo4j_deleted):
    full = client.get("/graph", headers=analyst_headers).json()
    host = next(n["name"] for n in full["nodes"] if n["label"] == "Host")

    found = client.get("/graph/entity", params={"type": "host", "value": host.upper()}, headers=analyst_headers)
    assert found.status_code == 200
    assert found.json()["nodes"]

    missing = client.get("/graph/entity", params={"type": "host", "value": "no-such-host"}, headers=analyst_headers)
    assert missing.status_code == 200
    assert missing.json() == {"nodes": [], "edges": []}


def test_blast_radius_respects_hop_limit(client, analyst_headers, seeded, neo4j_deleted):
    full = client.get("/graph", headers=analyst_headers).json()
    host = next(n["name"] for n in full["nodes"] if n["label"] == "Host")
    one = client.get("/graph/entity", params={"type": "host", "value": host, "hops": 1}, headers=analyst_headers).json()
    two = client.get("/graph/entity", params={"type": "host", "value": host, "hops": 2}, headers=analyst_headers).json()
    assert len(one["nodes"]) <= len(two["nodes"])


def test_digital_twin_and_sync_work_without_neo4j(client, analyst_headers, seeded, neo4j_deleted):
    full = client.get("/graph", headers=analyst_headers).json()
    host = next(n["name"] for n in full["nodes"] if n["label"] == "Host")

    twin = client.get("/digital-twin/simulate", params={"type": "host", "value": host}, headers=analyst_headers)
    assert twin.status_code == 200

    sync = client.post("/graph/sync", headers=analyst_headers)
    assert sync.status_code == 200
    assert sync.json()["backend"] == "postgres"
    assert sync.json()["incidents"] >= 1


def test_graph_is_scoped_to_the_callers_organization(client, analyst_headers, other_org_admin_headers, seeded, neo4j_deleted):
    other = client.get("/graph", headers=other_org_admin_headers)
    assert other.status_code == 200
    assert other.json() == {"nodes": [], "edges": []}


def test_threat_intel_graph_is_served_from_postgres_when_neo4j_is_deleted(client, analyst_headers, seeded, neo4j_deleted):
    response = client.get("/threat-intel/graph", headers=analyst_headers)
    assert response.status_code == 200
    graph = response.json()
    labels = {n["label"] for n in graph["nodes"]}
    assert {"Indicator", "Source"} <= labels
    types = {e["type"] for e in graph["edges"]}
    assert "REPORTED_BY" in types
    keys = {n["key"] for n in graph["nodes"]}
    assert all(e["from"] in keys and e["to"] in keys for e in graph["edges"])


def test_threat_intel_graph_sync_reports_postgres_backend(client, analyst_headers, seeded, neo4j_deleted):
    response = client.post("/threat-intel/graph/sync", headers=analyst_headers)
    assert response.status_code == 200, response.text
    assert response.json()["backend"] == "postgres"
