"""Cross-tenant isolation: organization A must never be able to see, list,
search, or modify organization B's data through any endpoint. Each test
below sets up two independent organizations with their own incidents and
proves the boundary holds - this is the actual security property multi-
tenancy exists to guarantee, so it gets its own dedicated file rather than
being folded into each feature's own test file (a few of the most
directly-relevant ones already got an inline cross-tenant test alongside
their feature - see test_auth.py, test_correlation.py, test_rag.py - this
file is the systematic sweep across every remaining endpoint)."""

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


def _create_incident(client, headers) -> int:
    client.post("/simulate/phishing_ransomware", headers=headers)
    client.post("/correlate", headers=headers)
    return client.get("/incidents", headers=headers).json()["incidents"][0]["id"]


def _run_investigation(client, headers, incident_id):
    with ExitStack() as stack:
        stack.enter_context(patch("app.agents.detection.chat_json", return_value=FAKE_DETECTION))
        stack.enter_context(patch("app.agents.investigation.chat_json", return_value=FAKE_INVESTIGATION))
        stack.enter_context(patch("app.agents.threat_intel.chat_json", return_value=FAKE_THREAT_INTEL))
        stack.enter_context(patch("app.agents.risk.chat_json", return_value=FAKE_RISK))
        stack.enter_context(patch("app.agents.response.chat_json", return_value=FAKE_RESPONSE))
        stack.enter_context(patch("app.agents.report.chat_json", return_value=FAKE_REPORT))
        return client.post(f"/incidents/{incident_id}/investigate", headers=headers)


def test_incident_detail_not_visible_across_organizations(client, admin_headers, other_org_admin_headers):
    incident_id = _create_incident(client, admin_headers)
    response = client.get(f"/incidents/{incident_id}", headers=other_org_admin_headers)
    assert response.status_code == 404


def test_incident_list_does_not_include_other_organizations(client, admin_headers, other_org_admin_headers):
    my_id = _create_incident(client, admin_headers)
    other_id = _create_incident(client, other_org_admin_headers)

    mine = client.get("/incidents", headers=admin_headers).json()["incidents"]
    theirs = client.get("/incidents", headers=other_org_admin_headers).json()["incidents"]

    assert my_id in [i["id"] for i in mine]
    assert other_id not in [i["id"] for i in mine]
    assert other_id in [i["id"] for i in theirs]
    assert my_id not in [i["id"] for i in theirs]


def test_incident_update_blocked_across_organizations(client, admin_headers, other_org_admin_headers):
    incident_id = _create_incident(client, admin_headers)
    response = client.patch(
        f"/incidents/{incident_id}", json={"status": "closed"}, headers=other_org_admin_headers
    )
    assert response.status_code == 404


def test_incident_comment_blocked_across_organizations(client, admin_headers, other_org_admin_headers):
    incident_id = _create_incident(client, admin_headers)
    response = client.post(
        f"/incidents/{incident_id}/comments", json={"body": "hi"}, headers=other_org_admin_headers
    )
    assert response.status_code == 404


def test_events_list_does_not_include_other_organizations(client, admin_headers, other_org_admin_headers):
    _create_incident(client, admin_headers)
    _create_incident(client, other_org_admin_headers)

    mine = client.get("/events", headers=admin_headers).json()["events"]
    theirs = client.get("/events", headers=other_org_admin_headers).json()["events"]

    mine_ids = {e["id"] for e in mine}
    theirs_ids = {e["id"] for e in theirs}
    assert mine_ids.isdisjoint(theirs_ids)
    assert len(mine) > 0 and len(theirs) > 0


def test_event_explain_blocked_across_organizations(client, admin_headers, other_org_admin_headers):
    _create_incident(client, admin_headers)
    event_id = client.get("/events", headers=admin_headers).json()["events"][0]["id"]

    response = client.get(f"/events/{event_id}/explain", headers=other_org_admin_headers)
    assert response.status_code == 404


def test_assets_list_does_not_include_other_organizations(client, admin_headers, other_org_admin_headers):
    _create_incident(client, admin_headers)
    _create_incident(client, other_org_admin_headers)

    mine = client.get("/assets", headers=admin_headers).json()["assets"]
    theirs = client.get("/assets", headers=other_org_admin_headers).json()["assets"]

    mine_ids = {a["id"] for a in mine}
    theirs_ids = {a["id"] for a in theirs}
    assert mine_ids.isdisjoint(theirs_ids)


def test_asset_update_blocked_across_organizations(client, admin_headers, other_org_admin_headers):
    _create_incident(client, admin_headers)
    asset_id = client.get("/assets", headers=admin_headers).json()["assets"][0]["id"]

    response = client.patch(f"/assets/{asset_id}", json={"department": "hacked"}, headers=other_org_admin_headers)
    assert response.status_code == 404


def test_two_organizations_can_have_the_same_hostname(client, admin_headers, other_org_admin_headers):
    """Both simulate scenarios create a FINANCE-PC-21 asset - the composite
    (organization_id, lower(host)) unique index must allow this, not
    collide the way a bare lower(host) index would have before multi-tenancy."""
    _create_incident(client, admin_headers)
    _create_incident(client, other_org_admin_headers)

    mine = [a for a in client.get("/assets", headers=admin_headers).json()["assets"] if a["host"].upper() == "FINANCE-PC-21"]
    theirs = [
        a for a in client.get("/assets", headers=other_org_admin_headers).json()["assets"] if a["host"].upper() == "FINANCE-PC-21"
    ]
    assert len(mine) == 1
    assert len(theirs) == 1
    assert mine[0]["id"] != theirs[0]["id"]


def test_stats_are_scoped_to_own_organization(client, admin_headers, other_org_admin_headers):
    _create_incident(client, admin_headers)
    _create_incident(client, other_org_admin_headers)
    _create_incident(client, other_org_admin_headers)  # a second, unrelated incident bumps org B's own count

    mine = client.get("/stats", headers=admin_headers).json()
    theirs = client.get("/stats", headers=other_org_admin_headers).json()

    assert mine["total_incidents"] == 1
    assert theirs["total_incidents"] == 2


def test_search_does_not_return_other_organizations_data(client, admin_headers, other_org_admin_headers):
    _create_incident(client, admin_headers)
    _create_incident(client, other_org_admin_headers)

    mine = client.get("/search", params={"q": "FINANCE-PC-21"}, headers=admin_headers).json()
    theirs = client.get("/search", params={"q": "FINANCE-PC-21"}, headers=other_org_admin_headers).json()

    mine_incident_ids = {i["id"] for i in mine["incidents"]}
    theirs_incident_ids = {i["id"] for i in theirs["incidents"]}
    assert mine_incident_ids.isdisjoint(theirs_incident_ids)


def test_rag_search_does_not_return_other_organizations_data(client, admin_headers, other_org_admin_headers):
    _create_incident(client, admin_headers)
    _create_incident(client, other_org_admin_headers)

    mine = client.get("/rag/search", params={"q": "ransomware finance"}, headers=admin_headers).json()["results"]
    theirs = client.get(
        "/rag/search", params={"q": "ransomware finance"}, headers=other_org_admin_headers
    ).json()["results"]

    mine_incident_ids = {r["content_id"] for r in mine if r["content_type"] == "incident"}
    theirs_incident_ids = {r["content_id"] for r in theirs if r["content_type"] == "incident"}
    assert mine_incident_ids.isdisjoint(theirs_incident_ids)


def test_similar_incidents_does_not_cross_organizations(client, admin_headers, other_org_admin_headers):
    my_id = _create_incident(client, admin_headers)
    other_id = _create_incident(client, other_org_admin_headers)

    matches = client.get(f"/incidents/{my_id}/similar", headers=admin_headers).json()["matches"]
    assert other_id not in [m["id"] for m in matches]


def test_incident_memory_does_not_cross_organizations(client, admin_headers, other_org_admin_headers):
    """The Milestone 3 "institutional memory" feature - repeat hosts/users
    and similar past incidents - must never surface another tenant's
    incident history to the AI agents or the analyst reading this endpoint."""
    _create_incident(client, admin_headers)
    other_id = _create_incident(client, other_org_admin_headers)

    # a second incident in org A sharing FINANCE-PC-21 with the first, so
    # repeat_hosts has something to find *within* org A
    client.post(
        "/ingest/generic",
        json={"logs": [{
            "timestamp": "2026-07-26T12:00:00",
            "host": "FINANCE-PC-21",
            "user": "j.mehta",
            "event_type": "login_failed",
            "severity": "high",
            "detail": "second incident same host",
            "source_ip": "185.220.101.45",
        }]},
        headers=admin_headers,
    )
    client.post("/correlate", headers=admin_headers)
    incidents = client.get("/incidents", headers=admin_headers).json()["incidents"]
    newest_id = max(i["id"] for i in incidents)

    memory = client.get(f"/incidents/{newest_id}/memory", headers=admin_headers).json()
    all_referenced_ids = (
        [s["incident_id"] for s in memory["similar_past_incidents"]]
        + [r["incident_id"] for r in memory["repeat_hosts"]]
        + [r["incident_id"] for r in memory["repeat_users"]]
    )
    assert other_id not in all_referenced_ids
    # sanity: org A's own repeat-host history was still found (proves this
    # isn't just trivially empty)
    assert any(r["incident_id"] in [i["id"] for i in incidents] for r in memory["repeat_hosts"])


def test_agent_runs_list_does_not_cross_organizations(client, admin_headers, other_org_admin_headers):
    my_incident = _create_incident(client, admin_headers)
    other_incident = _create_incident(client, other_org_admin_headers)
    my_run = _run_investigation(client, admin_headers, my_incident).json()["run_id"]
    other_run = _run_investigation(client, other_org_admin_headers, other_incident).json()["run_id"]

    mine = client.get("/agent-runs", headers=admin_headers).json()["runs"]
    theirs = client.get("/agent-runs", headers=other_org_admin_headers).json()["runs"]

    assert my_run in [r["id"] for r in mine]
    assert other_run not in [r["id"] for r in mine]
    assert other_run in [r["id"] for r in theirs]
    assert my_run not in [r["id"] for r in theirs]


def test_agent_run_detail_blocked_across_organizations(client, admin_headers, other_org_admin_headers):
    incident_id = _create_incident(client, admin_headers)
    run_id = _run_investigation(client, admin_headers, incident_id).json()["run_id"]

    response = client.get(f"/agent-runs/{run_id}", headers=other_org_admin_headers)
    assert response.status_code == 404


def test_incident_agent_runs_blocked_across_organizations(client, admin_headers, other_org_admin_headers):
    incident_id = _create_incident(client, admin_headers)
    _run_investigation(client, admin_headers, incident_id)

    response = client.get(f"/incidents/{incident_id}/agent-runs", headers=other_org_admin_headers)
    assert response.status_code == 404


def test_proposed_actions_blocked_across_organizations(client, admin_headers, other_org_admin_headers):
    incident_id = _create_incident(client, admin_headers)
    result = _run_investigation(client, admin_headers, incident_id)
    action_id = result.json()["response"]["proposed_actions"][0]["id"]

    list_response = client.get(f"/incidents/{incident_id}/proposed-actions", headers=other_org_admin_headers)
    assert list_response.status_code == 404

    review_response = client.patch(
        f"/proposed-actions/{action_id}", json={"status": "approved"}, headers=other_org_admin_headers
    )
    assert review_response.status_code == 404


def test_ws_agent_run_blocked_across_organizations(client, admin_headers, other_org_admin_headers):
    incident_id = _create_incident(client, admin_headers)
    run_id = _run_investigation(client, admin_headers, incident_id).json()["run_id"]
    other_token = other_org_admin_headers["Authorization"].split(" ")[1]

    with client.websocket_connect(f"/ws/agent-runs/{run_id}?token={other_token}") as ws:
        data = ws.receive_json()
        assert data["type"] == "error"
        assert "not found" in data["error"].lower()
