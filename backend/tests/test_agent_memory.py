from contextlib import ExitStack
from unittest.mock import patch

from tests.test_agents_coordinator import (
    FAKE_DETECTION,
    FAKE_INVESTIGATION,
    FAKE_REPORT,
    FAKE_RESPONSE,
    FAKE_RISK,
    FAKE_THREAT_INTEL,
)


def _create_incident_sharing_host(client, analyst_headers) -> tuple[int, int]:
    client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    client.post("/correlate", headers=analyst_headers)
    incident_1_id = client.get("/incidents", headers=analyst_headers).json()["incidents"][0]["id"]

    client.post(
        "/ingest/generic",
        json={
            "logs": [
                {
                    "timestamp": "2026-07-26T10:00:00",
                    "host": "FINANCE-PC-21",
                    "user": "j.mehta",
                    "event_type": "login_failed",
                    "severity": "high",
                    "detail": "A second, unrelated failed login on the same host",
                    "source_ip": "185.220.101.45",
                }
            ]
        },
        headers=analyst_headers,
    )
    client.post("/correlate", headers=analyst_headers)

    incidents = client.get("/incidents", headers=analyst_headers).json()["incidents"]
    incident_2_id = next(i["id"] for i in incidents if i["id"] != incident_1_id)
    return incident_1_id, incident_2_id


def _run_investigation(client, headers, incident_id, detection_side_effect=None, risk_side_effect=None):
    with ExitStack() as stack:
        stack.enter_context(
            patch("app.agents.detection.chat_json", side_effect=detection_side_effect, return_value=FAKE_DETECTION)
        )
        stack.enter_context(patch("app.agents.investigation.chat_json", return_value=FAKE_INVESTIGATION))
        stack.enter_context(patch("app.agents.threat_intel.chat_json", return_value=FAKE_THREAT_INTEL))
        stack.enter_context(patch("app.agents.risk.chat_json", side_effect=risk_side_effect, return_value=FAKE_RISK))
        stack.enter_context(patch("app.agents.response.chat_json", return_value=FAKE_RESPONSE))
        stack.enter_context(patch("app.agents.report.chat_json", return_value=FAKE_REPORT))
        return client.post(f"/incidents/{incident_id}/investigate", headers=headers)


def test_memory_endpoint_finds_repeat_host(client, analyst_headers):
    incident_1_id, incident_2_id = _create_incident_sharing_host(client, analyst_headers)

    response = client.get(f"/incidents/{incident_2_id}/memory", headers=analyst_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["incident_id"] == incident_2_id

    repeat_hosts = body["repeat_hosts"]
    match = next(r for r in repeat_hosts if r["incident_id"] == incident_1_id)
    assert "finance-pc-21" in match["shared"]


def test_memory_endpoint_finds_similar_past_incident(client, analyst_headers):
    incident_1_id, incident_2_id = _create_incident_sharing_host(client, analyst_headers)

    response = client.get(f"/incidents/{incident_2_id}/memory", headers=analyst_headers)
    similar_ids = [s["incident_id"] for s in response.json()["similar_past_incidents"]]
    assert incident_1_id in similar_ids


def test_memory_includes_prior_investigation_summary(client, analyst_headers):
    incident_1_id, incident_2_id = _create_incident_sharing_host(client, analyst_headers)
    _run_investigation(client, analyst_headers, incident_1_id)

    response = client.get(f"/incidents/{incident_2_id}/memory", headers=analyst_headers)
    similar = response.json()["similar_past_incidents"]
    match = next(s for s in similar if s["incident_id"] == incident_1_id)
    assert match["prior_report_summary"] == FAKE_REPORT["executive_summary"]


def test_memory_endpoint_unknown_incident_returns_404(client, analyst_headers):
    response = client.get("/incidents/99999/memory", headers=analyst_headers)
    assert response.status_code == 404


def test_memory_endpoint_requires_authentication(client):
    assert client.get("/incidents/1/memory").status_code == 401


def test_viewer_can_view_memory(client, analyst_headers, viewer_headers):
    _incident_1_id, incident_2_id = _create_incident_sharing_host(client, analyst_headers)
    response = client.get(f"/incidents/{incident_2_id}/memory", headers=viewer_headers)
    assert response.status_code == 200


def test_incident_with_no_history_has_empty_memory(client, analyst_headers):
    client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    client.post("/correlate", headers=analyst_headers)
    incident_id = client.get("/incidents", headers=analyst_headers).json()["incidents"][0]["id"]

    response = client.get(f"/incidents/{incident_id}/memory", headers=analyst_headers)
    body = response.json()
    assert body["similar_past_incidents"] == []
    assert body["repeat_hosts"] == []
    assert body["repeat_users"] == []


def test_investigation_passes_memory_context_to_detection_and_risk_agents(client, analyst_headers):
    """The Detection and Risk agents should actually receive the
    institutional-memory text in their prompt - not just have it computed
    and thrown away."""
    _incident_1_id, incident_2_id = _create_incident_sharing_host(client, analyst_headers)

    captured = {}

    def capture_detection(system_prompt, user_content, **kwargs):
        captured["detection"] = user_content
        return FAKE_DETECTION

    def capture_risk(system_prompt, user_content, **kwargs):
        captured["risk"] = user_content
        return FAKE_RISK

    response = _run_investigation(
        client, analyst_headers, incident_2_id, detection_side_effect=capture_detection, risk_side_effect=capture_risk
    )

    assert response.status_code == 200
    assert "finance-pc-21" in captured["detection"].lower()
    assert "finance-pc-21" in captured["risk"].lower()


def test_agent_run_result_persists_memory_context(client, analyst_headers):
    _incident_1_id, incident_2_id = _create_incident_sharing_host(client, analyst_headers)

    response = _run_investigation(client, analyst_headers, incident_2_id)
    run_id = response.json()["run_id"]

    detail = client.get(f"/agent-runs/{run_id}", headers=analyst_headers).json()
    assert detail["result"]["known_memory"]["repeat_hosts"]
