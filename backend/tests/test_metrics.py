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


def _create_incident(client, analyst_headers) -> int:
    client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    client.post("/correlate", headers=analyst_headers)
    return client.get("/incidents", headers=analyst_headers).json()["incidents"][0]["id"]


def _run_investigation(client, headers, incident_id, detection_side_effect=None):
    with ExitStack() as stack:
        stack.enter_context(
            patch("app.agents.detection.chat_json", side_effect=detection_side_effect, return_value=FAKE_DETECTION)
        )
        stack.enter_context(patch("app.agents.investigation.chat_json", return_value=FAKE_INVESTIGATION))
        stack.enter_context(patch("app.agents.threat_intel.chat_json", return_value=FAKE_THREAT_INTEL))
        stack.enter_context(patch("app.agents.risk.chat_json", return_value=FAKE_RISK))
        stack.enter_context(patch("app.agents.response.chat_json", return_value=FAKE_RESPONSE))
        stack.enter_context(patch("app.agents.report.chat_json", return_value=FAKE_REPORT))
        return client.post(f"/incidents/{incident_id}/investigate", headers=headers)


def test_metrics_endpoint_is_public_and_exposes_prometheus_format(client):
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]
    # a metric prometheus_fastapi_instrumentator always emits, proves the
    # instrumentator is actually wired in, not just importable
    assert "http_requests_total" in response.text


def test_completed_investigation_increments_metrics(client, analyst_headers):
    incident_id = _create_incident(client, analyst_headers)

    before = client.get("/metrics").text
    _run_investigation(client, analyst_headers, incident_id)
    after = client.get("/metrics").text

    assert 'sentraops_agent_investigations_total{status="completed"}' in after
    assert after.count('sentraops_agent_investigations_total{status="completed"}') >= 1
    assert "sentraops_agent_investigation_duration_seconds_count" in after
    assert before != after


def test_failed_investigation_increments_failed_metric(client, analyst_headers):
    from app.ai import ChatProviderError

    incident_id = _create_incident(client, analyst_headers)
    _run_investigation(client, analyst_headers, incident_id, detection_side_effect=ChatProviderError("rate limited"))

    after = client.get("/metrics").text
    assert 'sentraops_agent_investigations_total{status="failed"}' in after
