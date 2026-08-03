from unittest.mock import patch

import httpx

from tests.test_proposed_actions import _create_incident_with_proposed_actions


def test_list_connector_plugins(client, viewer_headers):
    response = client.get("/plugins/connectors", headers=viewer_headers)
    assert response.status_code == 200
    keys = {c["key"] for c in response.json()["connectors"]}
    assert keys == {"urlhaus", "github_events", "generic_rest"}


def test_list_response_action_plugins(client, viewer_headers):
    response = client.get("/plugins/response-actions", headers=viewer_headers)
    assert response.status_code == 200
    keys = {a["key"] for a in response.json()["actions"]}
    assert keys == {"webhook"}


def test_create_connector_requires_admin(client, analyst_headers, viewer_headers, admin_headers):
    payload = {"plugin_key": "urlhaus", "name": "Threat Feed", "config": {}}
    assert client.post("/connectors", json=payload, headers=viewer_headers).status_code == 403
    assert client.post("/connectors", json=payload, headers=analyst_headers).status_code == 403
    response = client.post("/connectors", json=payload, headers=admin_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["plugin_key"] == "urlhaus"
    assert body["enabled"] is True
    assert body["last_sync_status"] is None


def test_create_connector_rejects_unknown_plugin_key(client, admin_headers):
    response = client.post(
        "/connectors", json={"plugin_key": "not-a-real-plugin", "name": "x", "config": {}}, headers=admin_headers
    )
    assert response.status_code == 400


def test_connectors_scoped_to_organization(client, admin_headers, other_org_admin_headers):
    client.post("/connectors", json={"plugin_key": "urlhaus", "name": "Ours", "config": {}}, headers=admin_headers)

    own = client.get("/connectors", headers=admin_headers).json()["connectors"]
    other = client.get("/connectors", headers=other_org_admin_headers).json()["connectors"]
    assert len(own) == 1
    assert other == []


def test_test_connector_reports_failure_without_500(client, admin_headers):
    created = client.post(
        "/connectors", json={"plugin_key": "urlhaus", "name": "Threat Feed", "config": {}}, headers=admin_headers
    )
    connector_id = created.json()["id"]

    with patch("app.plugins.connectors.urlhaus.httpx.get", side_effect=httpx.ConnectError("network down")):
        response = client.post(f"/connectors/{connector_id}/test", headers=admin_headers)

    assert response.status_code == 200
    assert response.json()["ok"] is False


def test_sync_connector_ingests_events(client, admin_headers):
    created = client.post(
        "/connectors", json={"plugin_key": "urlhaus", "name": "Threat Feed", "config": {}}, headers=admin_headers
    )
    connector_id = created.json()["id"]

    fake_items = [
        {
            "timestamp": "2026-07-27 00:00:00",
            "host": "evil.example.com",
            "event_type": "malicious_url_reported",
            "severity": "high",
            "message": "URLhaus reported http://evil.example.com/x as malware_download",
        }
    ]
    with patch("app.plugins.connectors.urlhaus.UrlhausConnector.pull", return_value=fake_items):
        response = client.post(f"/connectors/{connector_id}/sync", headers=admin_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["ingested"] == 1
    assert body["connector"]["last_sync_status"] == "success"

    events = client.get("/events", headers=admin_headers).json()["events"]
    assert any(e["host"] == "evil.example.com" for e in events)


def test_sync_connector_records_failure_without_500(client, admin_headers):
    created = client.post(
        "/connectors", json={"plugin_key": "urlhaus", "name": "Threat Feed", "config": {}}, headers=admin_headers
    )
    connector_id = created.json()["id"]

    with patch("app.plugins.connectors.urlhaus.UrlhausConnector.pull", side_effect=RuntimeError("feed unreachable")):
        response = client.post(f"/connectors/{connector_id}/sync", headers=admin_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["ingested"] == 0
    assert body["connector"]["last_sync_status"] == "error"
    assert "feed unreachable" in body["connector"]["last_sync_message"]


def test_response_action_instance_crud_and_scoping(client, admin_headers, viewer_headers, other_org_admin_headers):
    payload = {"plugin_key": "webhook", "name": "SOC Slack", "config": {"webhook_url": "https://example.com/hook"}}
    assert client.post("/response-action-instances", json=payload, headers=viewer_headers).status_code == 403

    created = client.post("/response-action-instances", json=payload, headers=admin_headers)
    assert created.status_code == 200

    own = client.get("/response-action-instances", headers=admin_headers).json()["actions"]
    other = client.get("/response-action-instances", headers=other_org_admin_headers).json()["actions"]
    assert len(own) == 1
    assert other == []


def test_execute_proposed_action_requires_approval(client, analyst_headers, admin_headers):
    _, action_ids = _create_incident_with_proposed_actions(client, analyst_headers)
    client.post(
        "/response-action-instances",
        json={"plugin_key": "webhook", "name": "SOC Slack", "config": {"webhook_url": "https://example.com/hook"}},
        headers=admin_headers,
    )

    response = client.post(f"/proposed-actions/{action_ids[0]}/execute", headers=analyst_headers)
    assert response.status_code == 400


def test_execute_proposed_action_without_configured_integration(client, analyst_headers):
    _, action_ids = _create_incident_with_proposed_actions(client, analyst_headers)
    client.patch(f"/proposed-actions/{action_ids[0]}", json={"status": "approved"}, headers=analyst_headers)

    response = client.post(f"/proposed-actions/{action_ids[0]}/execute", headers=analyst_headers)
    assert response.status_code == 400


def test_execute_proposed_action_success(client, analyst_headers, admin_headers):
    _, action_ids = _create_incident_with_proposed_actions(client, analyst_headers)
    client.patch(f"/proposed-actions/{action_ids[0]}", json={"status": "approved"}, headers=analyst_headers)
    client.post(
        "/response-action-instances",
        json={"plugin_key": "webhook", "name": "SOC Slack", "config": {"webhook_url": "https://example.com/hook"}},
        headers=admin_headers,
    )

    with patch("app.plugins.actions.webhook.WebhookAction.execute", return_value=(True, "Webhook POST succeeded (200)")):
        response = client.post(f"/proposed-actions/{action_ids[0]}/execute", headers=analyst_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "executed"
    assert body["executed_at"]
    assert body["execution_result"][0]["ok"] is True


def test_execute_proposed_action_failure_sets_execution_failed(client, analyst_headers, admin_headers):
    _, action_ids = _create_incident_with_proposed_actions(client, analyst_headers)
    client.patch(f"/proposed-actions/{action_ids[0]}", json={"status": "approved"}, headers=analyst_headers)
    client.post(
        "/response-action-instances",
        json={"plugin_key": "webhook", "name": "SOC Slack", "config": {"webhook_url": "https://example.com/hook"}},
        headers=admin_headers,
    )

    with patch("app.plugins.actions.webhook.WebhookAction.execute", return_value=(False, "Webhook POST failed")):
        response = client.post(f"/proposed-actions/{action_ids[0]}/execute", headers=analyst_headers)

    assert response.status_code == 200
    assert response.json()["status"] == "execution_failed"


def test_cannot_execute_action_twice(client, analyst_headers, admin_headers):
    _, action_ids = _create_incident_with_proposed_actions(client, analyst_headers)
    client.patch(f"/proposed-actions/{action_ids[0]}", json={"status": "approved"}, headers=analyst_headers)
    client.post(
        "/response-action-instances",
        json={"plugin_key": "webhook", "name": "SOC Slack", "config": {"webhook_url": "https://example.com/hook"}},
        headers=admin_headers,
    )

    with patch("app.plugins.actions.webhook.WebhookAction.execute", return_value=(True, "ok")):
        client.post(f"/proposed-actions/{action_ids[0]}/execute", headers=analyst_headers)
        response = client.post(f"/proposed-actions/{action_ids[0]}/execute", headers=analyst_headers)

    assert response.status_code == 400
