from contextlib import ExitStack
from unittest.mock import patch

from app.ai import ChatConfigError, ChatProviderError

from tests.test_agents_coordinator import (
    FAKE_DETECTION,
    FAKE_INVESTIGATION,
    FAKE_REPORT,
    FAKE_RESPONSE,
    FAKE_RISK,
    FAKE_THREAT_INTEL,
)


def _create_incident(client, analyst_headers) -> int:
    client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    client.post("/correlate", headers=analyst_headers)
    return client.get("/incidents", headers=analyst_headers).json()["incidents"][0]["id"]


def _run_investigation(client, headers, incident_id):
    with ExitStack() as stack:
        stack.enter_context(patch("app.agents.detection.chat_json", return_value=FAKE_DETECTION))
        stack.enter_context(patch("app.agents.investigation.chat_json", return_value=FAKE_INVESTIGATION))
        stack.enter_context(patch("app.agents.threat_intel.chat_json", return_value=FAKE_THREAT_INTEL))
        stack.enter_context(patch("app.agents.risk.chat_json", return_value=FAKE_RISK))
        stack.enter_context(patch("app.agents.response.chat_json", return_value=FAKE_RESPONSE))
        stack.enter_context(patch("app.agents.report.chat_json", return_value=FAKE_REPORT))
        return client.post(f"/incidents/{incident_id}/investigate", headers=headers)


def test_completed_run_is_persisted_and_listed(client, analyst_headers):
    incident_id = _create_incident(client, analyst_headers)
    investigate_response = _run_investigation(client, analyst_headers, incident_id)
    run_id = investigate_response.json()["run_id"]

    list_response = client.get(f"/incidents/{incident_id}/agent-runs", headers=analyst_headers)
    assert list_response.status_code == 200
    runs = list_response.json()["runs"]
    assert len(runs) == 1
    assert runs[0]["id"] == run_id
    assert runs[0]["status"] == "completed"
    assert runs[0]["stage"] == "done"
    assert runs[0]["triggered_by_email"]

    detail_response = client.get(f"/agent-runs/{run_id}", headers=analyst_headers)
    assert detail_response.status_code == 200
    detail = detail_response.json()
    assert detail["status"] == "completed"
    assert detail["result"]["detection"]["attack_pattern"] == "credential theft + lateral movement"
    assert len(detail["messages"]) == 6
    assert detail["messages"][0]["agent"] == "detection"


def test_failed_run_is_still_persisted(client, analyst_headers):
    incident_id = _create_incident(client, analyst_headers)

    with patch("app.agents.detection.chat_json", side_effect=ChatProviderError("rate limited")):
        response = client.post(f"/incidents/{incident_id}/investigate", headers=analyst_headers)
    assert response.status_code == 502

    runs = client.get(f"/incidents/{incident_id}/agent-runs", headers=analyst_headers).json()["runs"]
    assert len(runs) == 1
    assert runs[0]["status"] == "failed"

    detail = client.get(f"/agent-runs/{runs[0]['id']}", headers=analyst_headers).json()
    assert detail["error"] == "rate limited"


def test_failed_run_config_error_is_persisted(client, analyst_headers):
    incident_id = _create_incident(client, analyst_headers)

    with patch("app.agents.detection.chat_json", side_effect=ChatConfigError("GROQ_API_KEY is not set")):
        response = client.post(f"/incidents/{incident_id}/investigate", headers=analyst_headers)
    assert response.status_code == 503

    runs = client.get(f"/incidents/{incident_id}/agent-runs", headers=analyst_headers).json()["runs"]
    assert runs[0]["status"] == "failed"


def test_agent_runs_unknown_incident_returns_404(client, analyst_headers):
    response = client.get("/incidents/99999/agent-runs", headers=analyst_headers)
    assert response.status_code == 404


def test_agent_run_unknown_id_returns_404(client, analyst_headers):
    response = client.get("/agent-runs/99999", headers=analyst_headers)
    assert response.status_code == 404


def test_viewer_can_view_agent_runs(client, analyst_headers, viewer_headers):
    incident_id = _create_incident(client, analyst_headers)
    _run_investigation(client, analyst_headers, incident_id)

    response = client.get(f"/incidents/{incident_id}/agent-runs", headers=viewer_headers)
    assert response.status_code == 200


def test_agent_runs_require_authentication(client):
    assert client.get("/incidents/1/agent-runs").status_code == 401
    assert client.get("/agent-runs/1").status_code == 401
