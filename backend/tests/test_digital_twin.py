from unittest.mock import patch

from neo4j.exceptions import ServiceUnavailable

from app.ai import ChatConfigError, ChatProviderError
from app.db_models import Asset
from app.digital_twin import simulate_compromise


def _graph(*hosts: str) -> dict:
    nodes = [{"key": f"Host:{h}", "label": "Host", "name": h} for h in hosts]
    nodes.append({"key": "Incident:1", "label": "Incident", "id": 1, "title": "t", "risk_level": "high", "status": "open"})
    return {"nodes": nodes, "edges": []}


def test_simulate_compromise_with_no_reachable_hosts(db_session, org_id):
    with patch("app.digital_twin.get_entity_blast_radius", return_value={"nodes": [], "edges": []}):
        result = simulate_compromise(db_session, "host", "nowhere", org_id)
    assert result["reachable_hosts"] == 0
    assert result["affected_assets"] == []
    assert result["business_impact_pct"] == 0


def test_simulate_compromise_cross_references_real_asset_criticality(db_session, org_id):
    db_session.add_all([
        Asset(organization_id=org_id, host="finance-pc-21", criticality="critical", department="Finance", owner="j.mehta"),
        Asset(organization_id=org_id, host="web-01", criticality="low"),
    ])
    db_session.commit()

    with patch("app.digital_twin.get_entity_blast_radius", return_value=_graph("finance-pc-21", "web-01")):
        result = simulate_compromise(db_session, "user", "attacker", org_id)

    assert result["reachable_hosts"] == 2
    assert result["related_incidents"] == 1
    # Most critical first.
    assert result["affected_assets"][0]["host"] == "finance-pc-21"
    assert result["affected_assets"][0]["criticality"] == "critical"
    assert result["affected_assets"][0]["department"] == "Finance"
    assert result["affected_assets"][1]["host"] == "web-01"
    assert result["affected_assets"][1]["criticality"] == "low"
    # impact = 4 (critical) + 1 (low) = 5, max possible = 2 hosts * 4 = 8 -> 62.5% (round-half-to-even -> 62)
    assert result["business_impact_score"] == 5
    assert result["business_impact_pct"] == 62


def test_simulate_compromise_host_without_asset_record_reports_unknown_criticality(db_session, org_id):
    with patch("app.digital_twin.get_entity_blast_radius", return_value=_graph("ghost-host")):
        result = simulate_compromise(db_session, "host", "ghost-host", org_id)
    assert result["affected_assets"] == [{"host": "ghost-host", "criticality": "unknown", "department": None, "owner": None}]
    # "unknown" isn't in CRITICALITY_WEIGHT, falls back to 1 -> 1/4 = 25%
    assert result["business_impact_pct"] == 25


def test_digital_twin_simulate_endpoint(client, viewer_headers):
    with patch("app.main.simulate_compromise", return_value={"entity_type": "host", "entity_value": "x", "hops": 2, "reachable_hosts": 0, "affected_assets": []}):
        response = client.get("/digital-twin/simulate", params={"type": "host", "value": "x"}, headers=viewer_headers)
    assert response.status_code == 200
    assert response.json()["reachable_hosts"] == 0


def test_digital_twin_simulate_returns_503_when_neo4j_unavailable(client, viewer_headers):
    with patch("app.main.simulate_compromise", side_effect=ServiceUnavailable("down")):
        response = client.get("/digital-twin/simulate", params={"type": "host", "value": "x"}, headers=viewer_headers)
    assert response.status_code == 503


def test_digital_twin_simulate_requires_authentication(client):
    assert client.get("/digital-twin/simulate", params={"type": "host", "value": "x"}).status_code == 401


def test_digital_twin_narrative_success(client, viewer_headers):
    fake_simulation = {"entity_type": "host", "entity_value": "x", "hops": 2, "reachable_hosts": 0, "affected_assets": []}
    fake_narrative = {
        "lateral_movement_narrative": "n/a",
        "affected_systems": [],
        "business_impact": "minimal",
        "estimated_recovery": "n/a",
        "confidence": "low",
    }
    with patch("app.main.simulate_compromise", return_value=fake_simulation), patch(
        "app.main.generate_twin_narrative", return_value=fake_narrative
    ):
        response = client.post("/digital-twin/narrative", params={"type": "host", "value": "x"}, headers=viewer_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["narrative"] == fake_narrative
    assert body["simulation"] == fake_simulation


def test_digital_twin_narrative_not_configured(client, viewer_headers):
    fake_simulation = {"entity_type": "host", "entity_value": "x", "hops": 2, "reachable_hosts": 0, "affected_assets": []}
    with patch("app.main.simulate_compromise", return_value=fake_simulation), patch(
        "app.main.generate_twin_narrative", side_effect=ChatConfigError("GROQ_API_KEY is not set")
    ):
        response = client.post("/digital-twin/narrative", params={"type": "host", "value": "x"}, headers=viewer_headers)
    assert response.status_code == 503


def test_digital_twin_narrative_provider_error(client, viewer_headers):
    fake_simulation = {"entity_type": "host", "entity_value": "x", "hops": 2, "reachable_hosts": 0, "affected_assets": []}
    with patch("app.main.simulate_compromise", return_value=fake_simulation), patch(
        "app.main.generate_twin_narrative", side_effect=ChatProviderError("rate limited")
    ):
        response = client.post("/digital-twin/narrative", params={"type": "host", "value": "x"}, headers=viewer_headers)
    assert response.status_code == 502


def test_digital_twin_narrative_requires_authentication(client):
    assert client.post("/digital-twin/narrative", params={"type": "host", "value": "x"}).status_code == 401
