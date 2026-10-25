from contextlib import ExitStack
from unittest.mock import patch

from neo4j.exceptions import ServiceUnavailable

from app.agents.graph_context import build_graph_context
from app.agents.state import format_graph_context
from app.db_models import Incident
from tests.test_agents_coordinator import FAKE_DETECTION, FAKE_REPORT, FAKE_RESPONSE, FAKE_RISK, FAKE_THREAT_INTEL


def _fake_incident(affected_hosts, organization_id=1, incident_id=1):
    return Incident(id=incident_id, organization_id=organization_id, title="t", affected_hosts=affected_hosts, affected_users=[])


def test_build_graph_context_unavailable_when_neo4j_down():
    incident = _fake_incident(["finance-pc-21"])
    with patch("app.agents.graph_context.get_entity_blast_radius", side_effect=ServiceUnavailable("down")):
        context = build_graph_context(incident)
    assert context == {"available": False, "connected_hosts": [], "connected_incident_count": 0}


def test_build_graph_context_no_affected_hosts_never_calls_neo4j():
    incident = _fake_incident([])
    with patch("app.agents.graph_context.get_entity_blast_radius") as mock_blast_radius:
        context = build_graph_context(incident)
    mock_blast_radius.assert_not_called()
    assert context == {"available": True, "connected_hosts": [], "connected_incident_count": 0}


def test_build_graph_context_aggregates_real_blast_radius_excluding_own_hosts():
    incident = _fake_incident(["finance-pc-21"])
    fake_subgraph = {
        "nodes": [
            {"label": "Host", "key": "Host:finance-pc-21", "name": "finance-pc-21"},  # own host - excluded
            {"label": "Host", "key": "Host:db-server-03", "name": "db-server-03"},
            {"label": "User", "key": "User:j.mehta", "name": "j.mehta"},  # not a Host/Incident - ignored
            {"label": "Incident", "key": "Incident:1", "id": 1, "title": "t", "risk_level": "high", "status": "open"},  # this incident itself - excluded
            {"label": "Incident", "key": "Incident:2", "id": 2, "title": "other", "risk_level": "high", "status": "open"},
        ],
        "edges": [],
    }
    with patch("app.agents.graph_context.get_entity_blast_radius", return_value=fake_subgraph) as mock_blast_radius:
        context = build_graph_context(incident)

    mock_blast_radius.assert_called_once_with("host", "finance-pc-21", 1, hops=2)
    assert context == {"available": True, "connected_hosts": ["db-server-03"], "connected_incident_count": 1}


def test_format_graph_context_unavailable():
    assert "not available" in format_graph_context({"available": False, "connected_hosts": [], "connected_incident_count": 0})


def test_format_graph_context_empty_but_available():
    text = format_graph_context({"available": True, "connected_hosts": [], "connected_incident_count": 0})
    assert "No other hosts or incidents" in text


def test_format_graph_context_with_hosts_and_incidents():
    text = format_graph_context({"available": True, "connected_hosts": ["db-server-03", "web-01"], "connected_incident_count": 2})
    assert "db-server-03" in text and "web-01" in text
    assert "2 other incident" in text


def test_investigation_passes_real_graph_context_to_investigation_and_risk_agents(client, analyst_headers):
    """Not just computed and thrown away: the real blast-radius text must
    actually reach the Investigation and Risk agents' prompts."""
    client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    client.post("/correlate", headers=analyst_headers)
    incident_id = client.get("/incidents", headers=analyst_headers).json()["incidents"][0]["id"]

    fake_graph_context = {"available": True, "connected_hosts": ["quarantine-host-99"], "connected_incident_count": 3}
    captured = {}

    def capture_investigation(system_prompt, user_content, **kwargs):
        captured["investigation"] = user_content
        return {"timeline_narrative": "n/a", "key_findings": [], "attacker_objective": "unclear"}

    def capture_risk(system_prompt, user_content, **kwargs):
        captured["risk"] = user_content
        return FAKE_RISK

    with ExitStack() as stack:
        stack.enter_context(patch("app.agents.runner.build_graph_context", return_value=fake_graph_context))
        stack.enter_context(patch("app.agents.detection.chat_json", return_value=FAKE_DETECTION))
        stack.enter_context(patch("app.agents.investigation.chat_json", side_effect=capture_investigation))
        stack.enter_context(patch("app.agents.threat_intel.chat_json", return_value=FAKE_THREAT_INTEL))
        stack.enter_context(patch("app.agents.risk.chat_json", side_effect=capture_risk))
        stack.enter_context(patch("app.agents.response.chat_json", return_value=FAKE_RESPONSE))
        stack.enter_context(patch("app.agents.report.chat_json", return_value=FAKE_REPORT))
        response = client.post(f"/incidents/{incident_id}/investigate", headers=analyst_headers)

    assert response.status_code == 200
    assert "quarantine-host-99" in captured["investigation"]
    assert "3 other incident" in captured["investigation"]
    assert "quarantine-host-99" in captured["risk"]
    assert "3 other incident" in captured["risk"]
