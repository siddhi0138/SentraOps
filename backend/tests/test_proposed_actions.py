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


def _create_incident_with_proposed_actions(client, analyst_headers) -> tuple[int, list[int]]:
    client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    client.post("/correlate", headers=analyst_headers)
    incident_id = client.get("/incidents", headers=analyst_headers).json()["incidents"][0]["id"]

    with ExitStack() as stack:
        stack.enter_context(patch("app.agents.detection.chat_json", return_value=FAKE_DETECTION))
        stack.enter_context(patch("app.agents.investigation.chat_json", return_value=FAKE_INVESTIGATION))
        stack.enter_context(patch("app.agents.threat_intel.chat_json", return_value=FAKE_THREAT_INTEL))
        stack.enter_context(patch("app.agents.risk.chat_json", return_value=FAKE_RISK))
        stack.enter_context(patch("app.agents.response.chat_json", return_value=FAKE_RESPONSE))
        stack.enter_context(patch("app.agents.report.chat_json", return_value=FAKE_REPORT))
        result = client.post(f"/incidents/{incident_id}/investigate", headers=analyst_headers)

    action_ids = [a["id"] for a in result.json()["response"]["proposed_actions"]]
    return incident_id, action_ids


def test_list_proposed_actions(client, analyst_headers):
    incident_id, action_ids = _create_incident_with_proposed_actions(client, analyst_headers)

    response = client.get(f"/incidents/{incident_id}/proposed-actions", headers=analyst_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["incident_id"] == incident_id
    assert [a["id"] for a in body["actions"]] == action_ids
    assert all(a["status"] == "pending" for a in body["actions"])


def test_approve_proposed_action(client, analyst_headers):
    _, action_ids = _create_incident_with_proposed_actions(client, analyst_headers)

    response = client.patch(f"/proposed-actions/{action_ids[0]}", json={"status": "approved"}, headers=analyst_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "approved"
    assert body["reviewed_by_email"]
    assert body["reviewed_at"]


def test_reject_proposed_action(client, analyst_headers):
    _, action_ids = _create_incident_with_proposed_actions(client, analyst_headers)

    response = client.patch(f"/proposed-actions/{action_ids[0]}", json={"status": "rejected"}, headers=analyst_headers)

    assert response.status_code == 200
    assert response.json()["status"] == "rejected"


def test_cannot_review_action_twice(client, analyst_headers):
    _, action_ids = _create_incident_with_proposed_actions(client, analyst_headers)

    client.patch(f"/proposed-actions/{action_ids[0]}", json={"status": "approved"}, headers=analyst_headers)
    response = client.patch(f"/proposed-actions/{action_ids[0]}", json={"status": "rejected"}, headers=analyst_headers)

    assert response.status_code == 400


def test_viewer_can_list_but_not_review(client, analyst_headers, viewer_headers):
    incident_id, action_ids = _create_incident_with_proposed_actions(client, analyst_headers)

    assert client.get(f"/incidents/{incident_id}/proposed-actions", headers=viewer_headers).status_code == 200
    assert client.patch(f"/proposed-actions/{action_ids[0]}", json={"status": "approved"}, headers=viewer_headers).status_code == 403


def test_review_unknown_action_returns_404(client, analyst_headers):
    response = client.patch("/proposed-actions/99999", json={"status": "approved"}, headers=analyst_headers)
    assert response.status_code == 404


def test_review_requires_authentication(client):
    response = client.patch("/proposed-actions/1", json={"status": "approved"})
    assert response.status_code == 401


def test_review_rejects_invalid_status(client, analyst_headers):
    _, action_ids = _create_incident_with_proposed_actions(client, analyst_headers)
    response = client.patch(f"/proposed-actions/{action_ids[0]}", json={"status": "maybe"}, headers=analyst_headers)
    assert response.status_code == 422
