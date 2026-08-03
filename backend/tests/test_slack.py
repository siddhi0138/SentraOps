import hashlib
import hmac
import time
from contextlib import ExitStack
from unittest.mock import patch

import jwt
import pytest

from app import slack_oauth
from app.db_models import ConnectorInstance, Incident, ProposedAction
from app.slack_bot import handle_review_action_button, notify_new_incident, notify_proposed_actions


def _slack_signature(secret: str, timestamp: str, body: bytes) -> str:
    basestring = b"v0:" + timestamp.encode() + b":" + body
    return "v0=" + hmac.new(secret.encode(), basestring, hashlib.sha256).hexdigest()


def _signed_headers(secret: str, body: bytes) -> dict:
    timestamp = str(int(time.time()))
    return {
        "X-Slack-Request-Timestamp": timestamp,
        "X-Slack-Signature": _slack_signature(secret, timestamp, body),
        "Content-Type": "application/x-www-form-urlencoded",
    }


# --- app/slack_oauth.py unit tests -----------------------------------------


def test_oauth_state_roundtrip():
    token = slack_oauth.sign_oauth_state(organization_id=7, user_id=3)
    claims = slack_oauth.verify_oauth_state(token)
    assert claims["org_id"] == 7
    assert claims["user_id"] == 3
    assert claims["purpose"] == "slack_oauth"


def test_oauth_state_rejects_tampered_token():
    token = slack_oauth.sign_oauth_state(organization_id=7, user_id=3)
    with pytest.raises(jwt.PyJWTError):
        slack_oauth.verify_oauth_state(token + "x")


def test_oauth_state_rejects_expired_token(monkeypatch):
    monkeypatch.setattr(slack_oauth, "_STATE_TTL_SECONDS", -1)
    token = slack_oauth.sign_oauth_state(organization_id=7, user_id=3)
    with pytest.raises(jwt.PyJWTError):
        slack_oauth.verify_oauth_state(token)


def test_verify_slack_signature_accepts_valid_request(monkeypatch):
    monkeypatch.setattr(slack_oauth, "SLACK_SIGNING_SECRET", "test-secret")
    body = b"team_id=T123&text=status"
    timestamp = str(int(time.time()))
    sig = _slack_signature("test-secret", timestamp, body)
    assert slack_oauth.verify_slack_signature(timestamp, body, sig) is True


def test_verify_slack_signature_rejects_wrong_secret(monkeypatch):
    monkeypatch.setattr(slack_oauth, "SLACK_SIGNING_SECRET", "test-secret")
    body = b"team_id=T123"
    timestamp = str(int(time.time()))
    sig = _slack_signature("wrong-secret", timestamp, body)
    assert slack_oauth.verify_slack_signature(timestamp, body, sig) is False


def test_verify_slack_signature_rejects_stale_timestamp(monkeypatch):
    monkeypatch.setattr(slack_oauth, "SLACK_SIGNING_SECRET", "test-secret")
    body = b"team_id=T123"
    stale_timestamp = str(int(time.time()) - 3600)
    sig = _slack_signature("test-secret", stale_timestamp, body)
    assert slack_oauth.verify_slack_signature(stale_timestamp, body, sig) is False


def test_verify_slack_signature_fails_closed_without_configured_secret(monkeypatch):
    monkeypatch.setattr(slack_oauth, "SLACK_SIGNING_SECRET", "")
    body = b"team_id=T123"
    timestamp = str(int(time.time()))
    assert slack_oauth.verify_slack_signature(timestamp, body, "v0=whatever") is False


# --- OAuth install endpoints -------------------------------------------------


def test_slack_authorize_requires_admin(client, viewer_headers):
    raw_token = viewer_headers["Authorization"].split(" ")[1]
    response = client.get("/connectors/slack/authorize", params={"token": raw_token})
    assert response.status_code == 403


def test_slack_authorize_redirects_to_slack_with_state(client, admin_headers, monkeypatch):
    monkeypatch.setattr("app.main.build_authorize_url", lambda state, redirect_uri: f"https://slack.com/oauth/v2/authorize?state={state}")
    raw_token = admin_headers["Authorization"].split(" ")[1]
    response = client.get("/connectors/slack/authorize", params={"token": raw_token}, follow_redirects=False)
    assert response.status_code in (302, 307)
    assert "slack.com" in response.headers["location"]


def test_slack_callback_creates_connector_instance(client, admin_headers, db_session):
    raw_token = admin_headers["Authorization"].split(" ")[1]
    from app.auth import decode_token
    user_id = decode_token(raw_token, "access")

    from app.db_models import User
    real_org_id = db_session.query(User).filter(User.id == user_id).one().organization_id
    state = slack_oauth.sign_oauth_state(organization_id=real_org_id, user_id=user_id)

    fake_token_response = {
        "ok": True,
        "access_token": "xoxb-fake",
        "team": {"id": "T123", "name": "Acme Corp"},
        "bot_user_id": "U999",
        "incoming_webhook": {"channel": "#security", "channel_id": "C123", "url": "https://hooks.slack.com/services/T123/B123/fake"},
    }
    with patch("app.main.exchange_code_for_token", return_value=fake_token_response), \
         patch("app.main.provision_default_channels", return_value={}) as mock_provision:
        response = client.get("/connectors/slack/callback", params={"code": "abc", "state": state}, follow_redirects=False)

    assert response.status_code in (302, 307)
    assert "slack=connected" in response.headers["location"]
    mock_provision.assert_called_once_with("xoxb-fake")

    instance = db_session.query(ConnectorInstance).filter(ConnectorInstance.plugin_key == "slack").one()
    assert instance.organization_id == real_org_id
    assert instance.config["access_token"] == "xoxb-fake"
    assert instance.config["team_id"] == "T123"
    assert instance.config["channel_id"] == "C123"
    assert instance.config["incoming_webhook_url"] == "https://hooks.slack.com/services/T123/B123/fake"
    assert instance.config["installed_by_user_id"] == user_id


def test_slack_callback_reinstall_preserves_existing_channel_routing(client, admin_headers, db_session):
    raw_token = admin_headers["Authorization"].split(" ")[1]
    from app.auth import decode_token
    from app.db_models import User

    user_id = decode_token(raw_token, "access")
    real_org_id = db_session.query(User).filter(User.id == user_id).one().organization_id

    # Simulate an org that already has Slack connected with custom channel
    # routing configured.
    db_session.add(ConnectorInstance(
        organization_id=real_org_id,
        plugin_key="slack",
        name="Slack (old)",
        config={
            "access_token": "xoxb-old",
            "critical_channel": "critical-incidents",
            "critical_channel_id": "C999",
            "soc_team_channel": "soc-team",
        },
    ))
    db_session.commit()

    state = slack_oauth.sign_oauth_state(organization_id=real_org_id, user_id=user_id)
    fake_token_response = {
        "ok": True,
        "access_token": "xoxb-new",
        "team": {"id": "T123", "name": "Acme Corp"},
        "bot_user_id": "U999",
        "incoming_webhook": {"channel": "#security", "channel_id": "C123", "url": "https://hooks.slack.com/services/T123/B123/fake"},
    }
    with patch("app.main.exchange_code_for_token", return_value=fake_token_response), \
         patch("app.main.provision_default_channels") as mock_provision:
        response = client.get("/connectors/slack/callback", params={"code": "abc", "state": state}, follow_redirects=False)

    assert response.status_code in (302, 307)
    # provision_default_channels is only for brand-new installs, never a
    # reinstall over an already-configured connector.
    mock_provision.assert_not_called()

    instance = db_session.query(ConnectorInstance).filter(ConnectorInstance.plugin_key == "slack").one()
    assert instance.config["access_token"] == "xoxb-new"  # the fresh token is used
    assert instance.config["critical_channel"] == "critical-incidents"  # preserved
    assert instance.config["critical_channel_id"] == "C999"  # preserved
    assert instance.config["soc_team_channel"] == "soc-team"  # preserved


def test_slack_callback_redirects_with_error_on_bad_state(client):
    response = client.get("/connectors/slack/callback", params={"code": "abc", "state": "garbage"}, follow_redirects=False)
    assert response.status_code in (302, 307)
    assert "slack=error" in response.headers["location"]


def test_slack_callback_redirects_with_error_when_slack_denies(client):
    response = client.get("/connectors/slack/callback", params={"error": "access_denied"}, follow_redirects=False)
    assert response.status_code in (302, 307)
    assert "slack=error" in response.headers["location"]


# --- /slack/commands ---------------------------------------------------------


def _install_slack_connector(db_session, organization_id: int, user_id: int, team_id: str = "T123") -> ConnectorInstance:
    instance = ConnectorInstance(
        organization_id=organization_id,
        plugin_key="slack",
        name="Slack (Test)",
        config={
            "access_token": "xoxb-fake",
            "team_id": team_id,
            "channel_id": "C123",
            "incoming_webhook_url": "https://hooks.slack.com/services/T123/B123/fake",
            "installed_by_user_id": user_id,
        },
    )
    db_session.add(instance)
    db_session.commit()
    db_session.refresh(instance)
    return instance


def test_slack_commands_rejects_unsigned_request(client):
    response = client.post("/slack/commands", data={"team_id": "T123", "text": "status"})
    assert response.status_code == 401


def test_slack_commands_status_for_unknown_workspace(client, monkeypatch):
    monkeypatch.setattr("app.slack_oauth.SLACK_SIGNING_SECRET", "test-secret")
    body = b"team_id=T-unknown&text=status"
    response = client.post("/slack/commands", content=body, headers=_signed_headers("test-secret", body))
    assert response.status_code == 200
    assert "isn't connected" in response.json()["text"]


def test_slack_commands_status_reports_real_counts(client, admin_headers, db_session, monkeypatch):
    raw_token = admin_headers["Authorization"].split(" ")[1]
    from app.auth import decode_token
    from app.db_models import User
    user_id = decode_token(raw_token, "access")
    org_id = db_session.query(User).filter(User.id == user_id).one().organization_id
    _install_slack_connector(db_session, org_id, user_id)

    client.post("/simulate/phishing_ransomware", headers=admin_headers)
    client.post("/correlate", headers=admin_headers)

    monkeypatch.setattr("app.slack_oauth.SLACK_SIGNING_SECRET", "test-secret")
    body = b"team_id=T123&text=status"
    response = client.post("/slack/commands", content=body, headers=_signed_headers("test-secret", body))

    assert response.status_code == 200
    assert "SentraOps status" in response.json()["text"]


def test_slack_commands_incidents_lists_open_incidents(client, admin_headers, db_session, monkeypatch):
    raw_token = admin_headers["Authorization"].split(" ")[1]
    from app.auth import decode_token
    from app.db_models import User
    user_id = decode_token(raw_token, "access")
    org_id = db_session.query(User).filter(User.id == user_id).one().organization_id
    _install_slack_connector(db_session, org_id, user_id)

    client.post("/simulate/phishing_ransomware", headers=admin_headers)
    client.post("/correlate", headers=admin_headers)

    monkeypatch.setattr("app.slack_oauth.SLACK_SIGNING_SECRET", "test-secret")
    body = b"team_id=T123&text=incidents"
    response = client.post("/slack/commands", content=body, headers=_signed_headers("test-secret", body))

    assert response.status_code == 200
    assert "Open incidents" in response.json()["text"]


def test_slack_commands_investigate_starts_a_real_run(client, admin_headers, db_session, monkeypatch):
    from app.auth import decode_token
    from app.db_models import AgentRun, User

    raw_token = admin_headers["Authorization"].split(" ")[1]
    user_id = decode_token(raw_token, "access")
    org_id = db_session.query(User).filter(User.id == user_id).one().organization_id
    _install_slack_connector(db_session, org_id, user_id)

    client.post("/simulate/phishing_ransomware", headers=admin_headers)
    correlate_res = client.post("/correlate", headers=admin_headers)
    incident_id = correlate_res.json()["incidents"][0]["id"]

    monkeypatch.setattr("app.slack_oauth.SLACK_SIGNING_SECRET", "test-secret")
    body = f"team_id=T123&text=investigate {incident_id}".encode()
    response = client.post("/slack/commands", content=body, headers=_signed_headers("test-secret", body))

    assert response.status_code == 200
    assert f"#{incident_id}" in response.json()["text"]
    run = db_session.query(AgentRun).filter(AgentRun.incident_id == incident_id).first()
    assert run is not None


# --- /slack/interactions -----------------------------------------------------


def test_slack_interactions_rejects_unsigned_request(client):
    response = client.post("/slack/interactions", data={"payload": "{}"})
    assert response.status_code == 401


def test_slack_interactions_review_action_approves_real_proposed_action(client, admin_headers, db_session, monkeypatch):
    from app.auth import decode_token
    from app.db_models import User

    raw_token = admin_headers["Authorization"].split(" ")[1]
    user_id = decode_token(raw_token, "access")
    org_id = db_session.query(User).filter(User.id == user_id).one().organization_id
    _install_slack_connector(db_session, org_id, user_id)

    incident = Incident(organization_id=org_id, title="t", risk_level="high", risk_score=80, priority="high")
    db_session.add(incident)
    db_session.flush()
    action = ProposedAction(organization_id=org_id, incident_id=incident.id, category="containment", description="Isolate host")
    db_session.add(action)
    db_session.commit()
    db_session.refresh(action)

    monkeypatch.setattr("app.slack_oauth.SLACK_SIGNING_SECRET", "test-secret")
    import json
    from urllib.parse import urlencode
    payload = {
        "team": {"id": "T123"},
        "user": {"username": "j.mehta"},
        "actions": [{"action_id": "review_action", "value": f"{action.id}:approved"}],
        "response_url": "https://hooks.slack.com/actions/T123/fake",
    }
    body = urlencode({"payload": json.dumps(payload)}).encode()

    with patch("app.main.httpx.post") as mock_post:
        response = client.post("/slack/interactions", content=body, headers=_signed_headers("test-secret", body))

    assert response.status_code == 200
    db_session.refresh(action)
    assert action.status == "approved"
    assert action.reviewed_by_id == user_id
    mock_post.assert_called_once()


# --- notify_new_incident / notify_proposed_actions (no-op without a connector) -----


def test_notify_new_incident_is_a_noop_without_slack_connector(db_session, org_id):
    incident = Incident(organization_id=org_id, title="t", risk_level="low", risk_score=10, priority="low")
    db_session.add(incident)
    db_session.commit()
    # Must not raise even though no Slack connector exists for this org.
    notify_new_incident(db_session, incident)


def test_notify_proposed_actions_is_a_noop_without_slack_connector(db_session, org_id):
    incident = Incident(organization_id=org_id, title="t", risk_level="low", risk_score=10, priority="low")
    db_session.add(incident)
    db_session.flush()
    action = ProposedAction(organization_id=org_id, incident_id=incident.id, category="containment", description="d")
    db_session.add(action)
    db_session.commit()
    notify_proposed_actions(db_session, incident=incident, proposed_actions=[action])


def test_notify_new_incident_posts_to_slack_when_connected(db_session, org_id):
    instance = ConnectorInstance(
        organization_id=org_id,
        plugin_key="slack",
        name="Slack",
        config={
            "access_token": "xoxb-fake",
            "channel_id": "C123",
            "team_id": "T123",
            "incoming_webhook_url": "https://hooks.slack.com/services/T123/B123/fake",
        },
    )
    db_session.add(instance)
    incident = Incident(organization_id=org_id, title="Ransomware", risk_level="critical", risk_score=95, priority="critical", affected_hosts=["host-1"])
    db_session.add(incident)
    db_session.commit()

    with patch("app.slack_bot.httpx.post") as mock_post:
        notify_new_incident(db_session, incident)

    mock_post.assert_called_once()
    assert mock_post.call_args.args[0] == "https://hooks.slack.com/services/T123/B123/fake"


# --- /sentraops ask and /sentraops hunt --------------------------------------


def test_slack_commands_ask_answers_with_confidence(client, admin_headers, db_session, monkeypatch):
    from app.auth import decode_token
    from app.db_models import User

    raw_token = admin_headers["Authorization"].split(" ")[1]
    user_id = decode_token(raw_token, "access")
    org_id = db_session.query(User).filter(User.id == user_id).one().organization_id
    _install_slack_connector(db_session, org_id, user_id)

    monkeypatch.setattr("app.slack_oauth.SLACK_SIGNING_SECRET", "test-secret")
    with patch("app.slack_bot.answer_question", return_value="This looks like credential theft."):
        body = b"team_id=T123&text=ask+why+is+this+critical"
        response = client.post("/slack/commands", content=body, headers=_signed_headers("test-secret", body))

    assert response.status_code == 200
    text = response.json()["text"]
    assert "credential theft" in text
    assert "Confidence:" in text


def test_slack_commands_ask_reports_when_ai_not_configured(client, admin_headers, db_session, monkeypatch):
    from app.auth import decode_token
    from app.db_models import User
    from app.ai import ChatConfigError

    raw_token = admin_headers["Authorization"].split(" ")[1]
    user_id = decode_token(raw_token, "access")
    org_id = db_session.query(User).filter(User.id == user_id).one().organization_id
    _install_slack_connector(db_session, org_id, user_id)

    monkeypatch.setattr("app.slack_oauth.SLACK_SIGNING_SECRET", "test-secret")
    with patch("app.slack_bot.answer_question", side_effect=ChatConfigError("GROQ_API_KEY is not set")):
        body = b"team_id=T123&text=ask+anything"
        response = client.post("/slack/commands", content=body, headers=_signed_headers("test-secret", body))

    assert response.status_code == 200
    assert "isn't configured" in response.json()["text"]


def test_slack_commands_hunt_finds_real_incidents(client, admin_headers, db_session, monkeypatch):
    from app.auth import decode_token
    from app.db_models import User

    raw_token = admin_headers["Authorization"].split(" ")[1]
    user_id = decode_token(raw_token, "access")
    org_id = db_session.query(User).filter(User.id == user_id).one().organization_id
    _install_slack_connector(db_session, org_id, user_id)

    client.post("/simulate/phishing_ransomware", headers=admin_headers)
    client.post("/correlate", headers=admin_headers)

    monkeypatch.setattr("app.slack_oauth.SLACK_SIGNING_SECRET", "test-secret")
    body = b"team_id=T123&text=hunt+ransomware"
    response = client.post("/slack/commands", content=body, headers=_signed_headers("test-secret", body))

    assert response.status_code == 200
    assert "incident" in response.json()["text"].lower()


def test_slack_commands_hunt_with_no_matches(client, admin_headers, db_session, monkeypatch):
    from app.auth import decode_token
    from app.db_models import User

    raw_token = admin_headers["Authorization"].split(" ")[1]
    user_id = decode_token(raw_token, "access")
    org_id = db_session.query(User).filter(User.id == user_id).one().organization_id
    _install_slack_connector(db_session, org_id, user_id)

    monkeypatch.setattr("app.slack_oauth.SLACK_SIGNING_SECRET", "test-secret")
    body = b"team_id=T123&text=hunt+nonexistent-topic-xyz"
    response = client.post("/slack/commands", content=body, headers=_signed_headers("test-secret", body))

    assert response.status_code == 200
    assert "No incidents found" in response.json()["text"]


# --- live per-agent progress + failure notifications --------------------------


def test_notify_agent_progress_posts_a_message(db_session, org_id):
    from app.db_models import AgentRun
    from app.slack_bot import notify_agent_progress

    instance = ConnectorInstance(
        organization_id=org_id,
        plugin_key="slack",
        name="Slack",
        config={"incoming_webhook_url": "https://hooks.slack.com/services/T123/B123/fake"},
    )
    db_session.add(instance)
    incident = Incident(organization_id=org_id, title="t", risk_level="high", risk_score=80, priority="high")
    db_session.add(incident)
    db_session.flush()
    run = AgentRun(organization_id=org_id, incident_id=incident.id, status="running")
    db_session.add(run)
    db_session.commit()

    with patch("app.slack_bot.httpx.post") as mock_post:
        notify_agent_progress(db_session, run, incident, "detection", "Found credential theft pattern.")

    mock_post.assert_called_once()
    assert mock_post.call_args.args[0] == "https://hooks.slack.com/services/T123/B123/fake"
    posted_text = mock_post.call_args.kwargs["json"]["text"]
    assert "Detection Agent" in posted_text
    assert "credential theft" in posted_text.lower()


def test_notify_agent_progress_routes_to_soc_team_channel_when_configured(db_session, org_id):
    from app.db_models import AgentRun
    from app.slack_bot import notify_agent_progress

    instance = ConnectorInstance(
        organization_id=org_id,
        plugin_key="slack",
        name="Slack",
        config={
            "access_token": "xoxb-fake",
            "incoming_webhook_url": "https://hooks.slack.com/services/T123/B123/fake",
            "soc_team_channel": "soc-team",
        },
    )
    db_session.add(instance)
    incident = Incident(organization_id=org_id, title="t", risk_level="high", risk_score=80, priority="high")
    db_session.add(incident)
    db_session.flush()
    run = AgentRun(organization_id=org_id, incident_id=incident.id, status="running")
    db_session.add(run)
    db_session.commit()

    with patch("app.slack_bot.httpx.get") as mock_get, patch("app.slack_bot.httpx.post") as mock_post:
        mock_get.return_value.json.return_value = {"ok": True, "channels": [{"id": "C999", "name": "soc-team"}]}
        mock_post.return_value.json.return_value = {"ok": True}
        notify_agent_progress(db_session, run, incident, "detection", "Found credential theft pattern.")

    # Goes only to the resolved soc-team channel via chat.postMessage, not
    # also to the default incoming-webhook channel - a message type with
    # exactly one configured home shouldn't double-post.
    mock_post.assert_called_once()
    assert "chat.postMessage" in mock_post.call_args.args[0]
    assert mock_post.call_args.kwargs["json"]["channel"] == "C999"


def test_notify_agent_progress_is_a_noop_without_connector(db_session, org_id):
    from app.db_models import AgentRun
    from app.slack_bot import notify_agent_progress

    incident = Incident(organization_id=org_id, title="t", risk_level="low", risk_score=10, priority="low")
    db_session.add(incident)
    db_session.flush()
    run = AgentRun(organization_id=org_id, incident_id=incident.id, status="running")
    db_session.add(run)
    db_session.commit()

    notify_agent_progress(db_session, run, incident, "detection", "message")


def test_notify_run_failed_posts_a_warning(db_session, org_id):
    from app.db_models import AgentRun
    from app.slack_bot import notify_run_failed

    instance = ConnectorInstance(
        organization_id=org_id,
        plugin_key="slack",
        name="Slack",
        config={"incoming_webhook_url": "https://hooks.slack.com/services/T123/B123/fake"},
    )
    db_session.add(instance)
    incident = Incident(organization_id=org_id, title="t", risk_level="high", risk_score=80, priority="high")
    db_session.add(incident)
    db_session.flush()
    run = AgentRun(organization_id=org_id, incident_id=incident.id, status="failed")
    db_session.add(run)
    db_session.commit()

    with patch("app.slack_bot.httpx.post") as mock_post:
        notify_run_failed(db_session, run, incident, "GROQ_API_KEY is not set")

    mock_post.assert_called_once()
    assert "GROQ_API_KEY" in mock_post.call_args.kwargs["json"]["text"]


def test_investigate_live_posts_progress_for_every_agent(client, admin_headers, db_session, monkeypatch):
    from app.auth import decode_token
    from app.db_models import User
    from tests.test_agents_coordinator import (
        FAKE_DETECTION,
        FAKE_INVESTIGATION,
        FAKE_REPORT,
        FAKE_RESPONSE,
        FAKE_RISK,
        FAKE_THREAT_INTEL,
    )

    raw_token = admin_headers["Authorization"].split(" ")[1]
    user_id = decode_token(raw_token, "access")
    org_id = db_session.query(User).filter(User.id == user_id).one().organization_id
    _install_slack_connector(db_session, org_id, user_id)

    client.post("/simulate/phishing_ransomware", headers=admin_headers)
    client.post("/correlate", headers=admin_headers)
    incident_id = client.get("/incidents", headers=admin_headers).json()["incidents"][0]["id"]

    with patch("app.slack_bot.httpx.post") as mock_post, ExitStack() as stack:
        stack.enter_context(patch("app.agents.detection.chat_json", return_value=FAKE_DETECTION))
        stack.enter_context(patch("app.agents.investigation.chat_json", return_value=FAKE_INVESTIGATION))
        stack.enter_context(patch("app.agents.threat_intel.chat_json", return_value=FAKE_THREAT_INTEL))
        stack.enter_context(patch("app.agents.risk.chat_json", return_value=FAKE_RISK))
        stack.enter_context(patch("app.agents.response.chat_json", return_value=FAKE_RESPONSE))
        stack.enter_context(patch("app.agents.report.chat_json", return_value=FAKE_REPORT))
        response = client.post(f"/incidents/{incident_id}/investigate-live", headers=admin_headers)

    assert response.status_code == 200
    # One post per agent (6) at minimum - possibly more if the Response
    # Agent's fake output includes proposed actions, which fire their own
    # separate Slack message per action (notify_proposed_actions).
    assert mock_post.call_count >= 6


# --- Learning Loop feedback notifications --------------------------------------


def test_record_feedback_posts_to_slack(client, admin_headers, db_session, monkeypatch):
    from app.auth import decode_token
    from app.db_models import User
    from app.learning import record_feedback

    raw_token = admin_headers["Authorization"].split(" ")[1]
    user_id = decode_token(raw_token, "access")
    org_id = db_session.query(User).filter(User.id == user_id).one().organization_id
    _install_slack_connector(db_session, org_id, user_id)

    incident = Incident(organization_id=org_id, title="t", risk_level="high", risk_score=80, priority="high")
    db_session.add(incident)
    db_session.commit()

    with patch("app.slack_bot.httpx.post") as mock_post:
        record_feedback(db_session, org_id, incident.id, "false_positive", "Not actually malicious", user_id)

    mock_post.assert_called_once()
    posted_text = mock_post.call_args.kwargs["json"]["text"]
    assert "False Positive" in posted_text
    assert "Not actually malicious" in posted_text


def test_record_feedback_is_a_noop_without_connector(db_session, org_id):
    from app.learning import record_feedback

    incident = Incident(organization_id=org_id, title="t", risk_level="low", risk_score=10, priority="low")
    db_session.add(incident)
    db_session.commit()

    feedback = record_feedback(db_session, org_id, incident.id, "accurate", None, reviewed_by_id=1)
    assert feedback.rating == "accurate"


# --- PATCH /connectors/{id} ---------------------------------------------------


def _org_id_for(db_session, headers) -> int:
    from app.auth import decode_token
    from app.db_models import User

    user_id = decode_token(headers["Authorization"].split(" ")[1], "access")
    return db_session.query(User).filter(User.id == user_id).one().organization_id


def test_update_connector_config_merges_and_requires_admin(client, admin_headers, analyst_headers, db_session):
    org_id = _org_id_for(db_session, admin_headers)
    instance = ConnectorInstance(organization_id=org_id, plugin_key="slack", name="Slack", config={"access_token": "xoxb-fake"})
    db_session.add(instance)
    db_session.commit()
    db_session.refresh(instance)

    denied = client.patch(f"/connectors/{instance.id}", json={"config": {"critical_channel": "critical-incidents"}}, headers=analyst_headers)
    assert denied.status_code == 403

    response = client.patch(f"/connectors/{instance.id}", json={"config": {"critical_channel": "critical-incidents"}}, headers=admin_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["config"]["critical_channel"] == "critical-incidents"
    assert body["config"]["access_token"] == "xoxb-fake"  # merged, not replaced


def test_update_connector_config_clears_cached_channel_id_on_change(client, admin_headers, db_session):
    org_id = _org_id_for(db_session, admin_headers)
    instance = ConnectorInstance(
        organization_id=org_id,
        plugin_key="slack",
        name="Slack",
        config={"critical_channel": "old-channel", "critical_channel_id": "C999"},
    )
    db_session.add(instance)
    db_session.commit()
    db_session.refresh(instance)

    response = client.patch(f"/connectors/{instance.id}", json={"config": {"critical_channel": "new-channel"}}, headers=admin_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["config"]["critical_channel"] == "new-channel"
    assert "critical_channel_id" not in body["config"]


def test_update_connector_config_scoped_to_organization(client, admin_headers, other_org_admin_headers, db_session):
    org_id = _org_id_for(db_session, admin_headers)
    instance = ConnectorInstance(organization_id=org_id, plugin_key="slack", name="Slack", config={})
    db_session.add(instance)
    db_session.commit()
    db_session.refresh(instance)

    response = client.patch(f"/connectors/{instance.id}", json={"config": {"critical_channel": "x"}}, headers=other_org_admin_headers)
    assert response.status_code == 404


# --- critical-channel routing ------------------------------------------------


def test_resolve_channel_id_finds_matching_channel():
    from app.slack_bot import _resolve_channel_id

    fake_response_data = {"ok": True, "channels": [{"id": "C111", "name": "general"}, {"id": "C222", "name": "critical-incidents"}]}
    with patch("app.slack_bot.httpx.get") as mock_get:
        mock_get.return_value.json.return_value = fake_response_data
        channel_id = _resolve_channel_id("xoxb-fake", "#critical-incidents")

    assert channel_id == "C222"


def test_resolve_channel_id_returns_none_when_not_found():
    from app.slack_bot import _resolve_channel_id

    with patch("app.slack_bot.httpx.get") as mock_get:
        mock_get.return_value.json.return_value = {"ok": True, "channels": [{"id": "C111", "name": "general"}]}
        channel_id = _resolve_channel_id("xoxb-fake", "nonexistent")

    assert channel_id is None


def test_create_or_find_channel_creates_a_new_channel():
    from app.slack_bot import _create_or_find_channel

    with patch("app.slack_bot.httpx.post") as mock_post:
        mock_post.return_value.json.return_value = {"ok": True, "channel": {"id": "C123", "name": "soc-team"}}
        channel_id = _create_or_find_channel("xoxb-fake", "soc-team")

    assert channel_id == "C123"
    assert mock_post.call_args.kwargs["data"]["name"] == "soc-team"


def test_create_or_find_channel_falls_back_to_lookup_when_name_taken():
    from app.slack_bot import _create_or_find_channel

    with patch("app.slack_bot.httpx.post") as mock_post, patch("app.slack_bot.httpx.get") as mock_get:
        mock_post.return_value.json.return_value = {"ok": False, "error": "name_taken"}
        mock_get.return_value.json.return_value = {"ok": True, "channels": [{"id": "C456", "name": "soc-team"}]}
        channel_id = _create_or_find_channel("xoxb-fake", "soc-team")

    assert channel_id == "C456"


def test_create_or_find_channel_returns_none_on_other_errors():
    from app.slack_bot import _create_or_find_channel

    with patch("app.slack_bot.httpx.post") as mock_post:
        mock_post.return_value.json.return_value = {"ok": False, "error": "missing_scope"}
        channel_id = _create_or_find_channel("xoxb-fake", "soc-team")

    assert channel_id is None


def test_provision_default_channels_creates_all_four():
    from app.slack_bot import provision_default_channels

    created = []

    def fake_post(url, **kwargs):
        name = kwargs["data"]["name"]
        created.append(name)
        return _fake_json_response({"ok": True, "channel": {"id": f"C-{name}", "name": name}})

    with patch("app.slack_bot.httpx.post", side_effect=fake_post):
        config = provision_default_channels("xoxb-fake")

    assert set(created) == {"critical-incidents", "soc-team", "executive-security", "compliance"}
    assert config["critical_channel"] == "critical-incidents"
    assert config["critical_channel_id"] == "C-critical-incidents"
    assert config["soc_team_channel"] == "soc-team"
    assert config["executive_channel"] == "executive-security"
    assert config["compliance_channel"] == "compliance"


def test_provision_default_channels_skips_ones_that_fail():
    from app.slack_bot import provision_default_channels

    def fake_post(url, **kwargs):
        name = kwargs["data"]["name"]
        if name == "compliance":
            return _fake_json_response({"ok": False, "error": "missing_scope"})
        return _fake_json_response({"ok": True, "channel": {"id": f"C-{name}", "name": name}})

    with patch("app.slack_bot.httpx.post", side_effect=fake_post):
        config = provision_default_channels("xoxb-fake")

    assert "compliance_channel" not in config
    assert config["critical_channel"] == "critical-incidents"


def test_critical_incident_also_posts_to_configured_critical_channel(db_session, org_id):
    instance = ConnectorInstance(
        organization_id=org_id,
        plugin_key="slack",
        name="Slack",
        config={
            "access_token": "xoxb-fake",
            "incoming_webhook_url": "https://hooks.slack.com/services/T123/B123/fake",
            "critical_channel": "critical-incidents",
        },
    )
    db_session.add(instance)
    incident = Incident(organization_id=org_id, title="Ransomware", risk_level="critical", risk_score=98, priority="critical")
    db_session.add(incident)
    db_session.commit()

    with patch("app.slack_bot.httpx.post") as mock_post, patch("app.slack_bot.httpx.get") as mock_get:
        mock_get.return_value.json.return_value = {"ok": True, "channels": [{"id": "C222", "name": "critical-incidents"}]}
        mock_post.return_value.json.return_value = {"ok": True}
        notify_new_incident(db_session, incident)

    # Once via the default incoming webhook, once more via chat.postMessage
    # to the resolved critical channel.
    assert mock_post.call_count == 2
    urls_called = [call.args[0] for call in mock_post.call_args_list]
    assert "https://hooks.slack.com/services/T123/B123/fake" in urls_called
    assert any("chat.postMessage" in u for u in urls_called)

    db_session.refresh(instance)
    assert instance.config["critical_channel_id"] == "C222"


def test_non_critical_incident_does_not_use_critical_channel(db_session, org_id):
    instance = ConnectorInstance(
        organization_id=org_id,
        plugin_key="slack",
        name="Slack",
        config={
            "access_token": "xoxb-fake",
            "incoming_webhook_url": "https://hooks.slack.com/services/T123/B123/fake",
            "critical_channel": "critical-incidents",
        },
    )
    db_session.add(instance)
    incident = Incident(organization_id=org_id, title="Suspicious login", risk_level="medium", risk_score=40, priority="medium")
    db_session.add(incident)
    db_session.commit()

    with patch("app.slack_bot.httpx.post") as mock_post:
        notify_new_incident(db_session, incident)

    mock_post.assert_called_once()  # only the default webhook, no critical-channel post


def test_critical_incident_without_critical_channel_configured_posts_once(db_session, org_id):
    instance = ConnectorInstance(
        organization_id=org_id,
        plugin_key="slack",
        name="Slack",
        config={"access_token": "xoxb-fake", "incoming_webhook_url": "https://hooks.slack.com/services/T123/B123/fake"},
    )
    db_session.add(instance)
    incident = Incident(organization_id=org_id, title="Ransomware", risk_level="critical", risk_score=98, priority="critical")
    db_session.add(incident)
    db_session.commit()

    with patch("app.slack_bot.httpx.post") as mock_post:
        notify_new_incident(db_session, incident)

    mock_post.assert_called_once()


# --- daily summary (Celery Beat) ----------------------------------------------


def test_send_daily_summaries_posts_briefing_per_connected_org(db_session, org_id):
    from app.slack_bot import send_daily_summaries

    instance = ConnectorInstance(
        organization_id=org_id,
        plugin_key="slack",
        name="Slack",
        config={"incoming_webhook_url": "https://hooks.slack.com/services/T123/B123/fake"},
    )
    db_session.add(instance)
    db_session.commit()

    fake_briefing = {"headline": "Quiet day", "summary": "No critical incidents in the last 24 hours."}
    with patch("app.slack_bot.generate_briefing", return_value=fake_briefing), patch("app.slack_bot.httpx.post") as mock_post:
        send_daily_summaries(db_session)

    mock_post.assert_called_once()
    posted_text = mock_post.call_args.kwargs["json"]["text"]
    assert "Quiet day" in posted_text


def test_send_daily_summaries_routes_to_executive_channel_when_configured(db_session, org_id):
    from app.slack_bot import send_daily_summaries

    instance = ConnectorInstance(
        organization_id=org_id,
        plugin_key="slack",
        name="Slack",
        config={
            "access_token": "xoxb-fake",
            "incoming_webhook_url": "https://hooks.slack.com/services/T123/B123/fake",
            "executive_channel": "executive-security",
        },
    )
    db_session.add(instance)
    db_session.commit()

    fake_briefing = {"headline": "Quiet day", "summary": "Nothing notable."}
    with patch("app.slack_bot.generate_briefing", return_value=fake_briefing), \
         patch("app.slack_bot.httpx.get") as mock_get, patch("app.slack_bot.httpx.post") as mock_post:
        mock_get.return_value.json.return_value = {"ok": True, "channels": [{"id": "C777", "name": "executive-security"}]}
        mock_post.return_value.json.return_value = {"ok": True}
        send_daily_summaries(db_session)

    mock_post.assert_called_once()
    assert mock_post.call_args.kwargs["json"]["channel"] == "C777"


def test_send_daily_summaries_skips_orgs_without_connector(db_session, org_id):
    from app.slack_bot import send_daily_summaries

    with patch("app.slack_bot.httpx.post") as mock_post:
        send_daily_summaries(db_session)

    mock_post.assert_not_called()


def test_send_daily_summaries_skips_org_when_ai_not_configured(db_session, org_id):
    from app.ai import ChatConfigError
    from app.slack_bot import send_daily_summaries

    instance = ConnectorInstance(
        organization_id=org_id,
        plugin_key="slack",
        name="Slack",
        config={"incoming_webhook_url": "https://hooks.slack.com/services/T123/B123/fake"},
    )
    db_session.add(instance)
    db_session.commit()

    with patch("app.slack_bot.generate_briefing", side_effect=ChatConfigError("no key")), patch("app.slack_bot.httpx.post") as mock_post:
        send_daily_summaries(db_session)

    mock_post.assert_not_called()


# --- send_report_to_slack (Download Report -> also send to Slack) -----------


def _fake_json_response(payload: dict):
    class _Resp:
        def json(self):
            return payload

        is_success = True
        status_code = 200

    return _Resp()


def test_send_report_to_slack_is_a_noop_without_connector(db_session, org_id):
    from app.slack_bot import send_report_to_slack

    incident = Incident(organization_id=org_id, title="t", risk_level="low", risk_score=10, priority="low", report="# Report body")
    db_session.add(incident)
    db_session.commit()

    ok, message = send_report_to_slack(db_session, incident)
    assert ok is False
    assert "isn't connected" in message


def test_send_report_to_slack_uploads_real_file(db_session, org_id):
    from app.slack_bot import send_report_to_slack

    instance = ConnectorInstance(
        organization_id=org_id,
        plugin_key="slack",
        name="Slack",
        config={"access_token": "xoxb-fake", "channel_id": "C123"},
    )
    db_session.add(instance)
    incident = Incident(
        organization_id=org_id, title="Ransomware", risk_level="critical", risk_score=95, priority="critical", report="# Full incident report\n\ndetails here"
    )
    db_session.add(incident)
    db_session.commit()

    def fake_post(url, **kwargs):
        if "getUploadURLExternal" in url:
            return _fake_json_response({"ok": True, "upload_url": "https://files.slack.com/upload/abc", "file_id": "F123"})
        if url == "https://files.slack.com/upload/abc":
            return _fake_json_response({"ok": True})
        if "completeUploadExternal" in url:
            return _fake_json_response({"ok": True})
        raise AssertionError(f"unexpected URL: {url}")

    with patch("app.slack_bot.httpx.post", side_effect=fake_post) as mock_post:
        ok, message = send_report_to_slack(db_session, incident)

    assert ok is True
    assert "sent" in message.lower()
    assert mock_post.call_count == 3
    # step 1 sends filename/length, step 3 shares into the org's real channel
    complete_call = mock_post.call_args_list[2]
    assert complete_call.kwargs["json"]["channel_id"] == "C123"


def test_send_report_to_slack_reports_upload_url_rejection():
    from app.slack_bot import send_report_to_slack

    db = None  # unused by the mocked path below

    class _Incident:
        id = 1
        title = "t"
        report = "body"
        organization_id = 99

    with patch("app.slack_bot.get_org_slack_connector") as mock_connector:
        mock_connector.return_value.config = {"access_token": "xoxb-fake", "channel_id": "C123"}
        with patch("app.slack_bot.httpx.post", return_value=_fake_json_response({"ok": False, "error": "invalid_auth"})):
            ok, message = send_report_to_slack(db, _Incident())

    assert ok is False
    assert "invalid_auth" in message


def test_send_incident_report_to_slack_endpoint(client, admin_headers, db_session):
    org_id = _org_id_for(db_session, admin_headers)
    _install_slack_connector(db_session, org_id, 1)

    incident = Incident(organization_id=org_id, title="t", risk_level="high", risk_score=80, priority="high", report="# report")
    db_session.add(incident)
    db_session.commit()
    db_session.refresh(incident)

    with patch("app.main.send_report_to_slack", return_value=(True, "Report sent to Slack")) as mock_send:
        response = client.post(f"/incidents/{incident.id}/report/send-to-slack", headers=admin_headers)

    assert response.status_code == 200
    assert response.json() == {"ok": True, "message": "Report sent to Slack"}
    mock_send.assert_called_once()


def test_send_incident_report_to_slack_endpoint_requires_authentication(client):
    response = client.post("/incidents/1/report/send-to-slack")
    assert response.status_code == 401


# --- multi-channel routing (soc-team / executive / compliance) --------------


def test_update_connector_config_invalidates_any_changed_channel_id(client, admin_headers, db_session):
    org_id = _org_id_for(db_session, admin_headers)
    instance = ConnectorInstance(
        organization_id=org_id,
        plugin_key="slack",
        name="Slack",
        config={
            "critical_channel": "old-critical",
            "critical_channel_id": "C1",
            "soc_team_channel": "old-soc",
            "soc_team_channel_id": "C2",
            "executive_channel": "unchanged-exec",
            "executive_channel_id": "C3",
        },
    )
    db_session.add(instance)
    db_session.commit()
    db_session.refresh(instance)

    response = client.patch(
        f"/connectors/{instance.id}",
        json={"config": {"critical_channel": "new-critical", "soc_team_channel": "new-soc"}},
        headers=admin_headers,
    )
    assert response.status_code == 200
    body = response.json()["config"]
    # Changed channels lose their cached id...
    assert "critical_channel_id" not in body
    assert "soc_team_channel_id" not in body
    # ...but an untouched channel's cached id survives.
    assert body["executive_channel_id"] == "C3"


def test_notify_compliance_report_routes_to_compliance_channel(db_session, org_id):
    from app.slack_bot import notify_compliance_report

    instance = ConnectorInstance(
        organization_id=org_id,
        plugin_key="slack",
        name="Slack",
        config={
            "access_token": "xoxb-fake",
            "incoming_webhook_url": "https://hooks.slack.com/services/T123/B123/fake",
            "compliance_channel": "compliance",
        },
    )
    db_session.add(instance)
    db_session.commit()

    report = {"overall_posture": "Mostly compliant", "summary": "2 controls need attention.", "gaps": [], "next_steps": ""}
    with patch("app.slack_bot.httpx.get") as mock_get, patch("app.slack_bot.httpx.post") as mock_post:
        mock_get.return_value.json.return_value = {"ok": True, "channels": [{"id": "C555", "name": "compliance"}]}
        mock_post.return_value.json.return_value = {"ok": True}
        notify_compliance_report(db_session, org_id, report)

    mock_post.assert_called_once()
    assert mock_post.call_args.kwargs["json"]["channel"] == "C555"
    assert "Mostly compliant" in mock_post.call_args.kwargs["json"]["text"]


def test_notify_compliance_report_falls_back_to_default_channel(db_session, org_id):
    from app.slack_bot import notify_compliance_report

    instance = ConnectorInstance(
        organization_id=org_id,
        plugin_key="slack",
        name="Slack",
        config={"incoming_webhook_url": "https://hooks.slack.com/services/T123/B123/fake"},
    )
    db_session.add(instance)
    db_session.commit()

    report = {"overall_posture": "Mostly compliant", "summary": "2 controls need attention."}
    with patch("app.slack_bot.httpx.post") as mock_post:
        notify_compliance_report(db_session, org_id, report)

    mock_post.assert_called_once()
    assert mock_post.call_args.args[0] == "https://hooks.slack.com/services/T123/B123/fake"


def test_notify_compliance_report_is_a_noop_without_connector(db_session, org_id):
    from app.slack_bot import notify_compliance_report

    # Must not raise even with no Slack connector for this org.
    notify_compliance_report(db_session, org_id, {"overall_posture": "x", "summary": "y"})


def test_compliance_report_endpoint_notifies_slack(client, admin_headers, db_session):
    org_id = _org_id_for(db_session, admin_headers)
    _install_slack_connector(db_session, org_id, 1)

    fake_report = {"overall_posture": "Mostly compliant", "summary": "s", "gaps": [], "next_steps": ""}
    with patch("app.main.generate_compliance_report", return_value=fake_report), patch("app.main.notify_compliance_report") as mock_notify:
        response = client.post("/compliance/report", headers=admin_headers)

    assert response.status_code == 200
    mock_notify.assert_called_once()
    assert mock_notify.call_args.args[1] == org_id
    assert mock_notify.call_args.args[2] == fake_report


# --- assignment / status-change / comment notifications ----------------------


def test_assigning_incident_notifies_slack(client, admin_headers, analyst_headers, db_session):
    from tests.test_incident_workflow import _create_one_incident

    org_id = _org_id_for(db_session, admin_headers)
    _install_slack_connector(db_session, org_id, 1)

    incident_id = _create_one_incident(client, analyst_headers)
    users = client.get("/users", headers=admin_headers).json()
    analyst_user_id = next(u["id"] for u in users if u["email"] == "analyst@example.com")

    with patch("app.main.notify_assignment") as mock_notify:
        response = client.patch(f"/incidents/{incident_id}", json={"assignee_id": analyst_user_id}, headers=admin_headers)

    assert response.status_code == 200
    mock_notify.assert_called_once()
    assert mock_notify.call_args.args[2].email == "analyst@example.com"


def test_unassigning_incident_does_not_notify_slack(client, admin_headers, analyst_headers, db_session):
    from tests.test_incident_workflow import _create_one_incident

    org_id = _org_id_for(db_session, admin_headers)
    _install_slack_connector(db_session, org_id, 1)

    incident_id = _create_one_incident(client, analyst_headers)
    users = client.get("/users", headers=admin_headers).json()
    analyst_user_id = next(u["id"] for u in users if u["email"] == "analyst@example.com")
    client.patch(f"/incidents/{incident_id}", json={"assignee_id": analyst_user_id}, headers=admin_headers)

    with patch("app.main.notify_assignment") as mock_notify:
        response = client.patch(f"/incidents/{incident_id}", json={"assignee_id": None}, headers=admin_headers)

    assert response.status_code == 200
    mock_notify.assert_not_called()


def test_changing_incident_status_notifies_slack(client, admin_headers, analyst_headers, db_session):
    from tests.test_incident_workflow import _create_one_incident

    org_id = _org_id_for(db_session, admin_headers)
    _install_slack_connector(db_session, org_id, 1)
    incident_id = _create_one_incident(client, analyst_headers)

    with patch("app.main.notify_status_change") as mock_notify:
        response = client.patch(f"/incidents/{incident_id}", json={"status": "closed"}, headers=admin_headers)

    assert response.status_code == 200
    mock_notify.assert_called_once()
    assert mock_notify.call_args.args[3] == "open"
    assert mock_notify.call_args.args[4] == "closed"


def test_setting_status_to_same_value_does_not_notify_slack(client, admin_headers, analyst_headers, db_session):
    from tests.test_incident_workflow import _create_one_incident

    org_id = _org_id_for(db_session, admin_headers)
    _install_slack_connector(db_session, org_id, 1)
    incident_id = _create_one_incident(client, analyst_headers)

    with patch("app.main.notify_status_change") as mock_notify:
        response = client.patch(f"/incidents/{incident_id}", json={"status": "open"}, headers=admin_headers)

    assert response.status_code == 200
    mock_notify.assert_not_called()


def test_priority_only_update_does_not_notify_status_or_assignment(client, admin_headers, analyst_headers, db_session):
    from tests.test_incident_workflow import _create_one_incident

    org_id = _org_id_for(db_session, admin_headers)
    _install_slack_connector(db_session, org_id, 1)
    incident_id = _create_one_incident(client, analyst_headers)

    with patch("app.main.notify_status_change") as mock_status, patch("app.main.notify_assignment") as mock_assign:
        response = client.patch(f"/incidents/{incident_id}", json={"priority": "low"}, headers=admin_headers)

    assert response.status_code == 200
    mock_status.assert_not_called()
    mock_assign.assert_not_called()


def test_commenting_on_incident_notifies_slack(client, admin_headers, analyst_headers, db_session):
    from tests.test_incident_workflow import _create_one_incident

    org_id = _org_id_for(db_session, admin_headers)
    _install_slack_connector(db_session, org_id, 1)
    incident_id = _create_one_incident(client, analyst_headers)

    with patch("app.main.notify_comment") as mock_notify:
        response = client.post(f"/incidents/{incident_id}/comments", json={"body": "Looks like a real threat."}, headers=analyst_headers)

    assert response.status_code == 200
    mock_notify.assert_called_once()
    assert mock_notify.call_args.args[3] == "Looks like a real threat."


def test_notify_assignment_posts_a_real_message(db_session, org_id):
    from app.db_models import User
    from app.slack_bot import notify_assignment

    instance = ConnectorInstance(
        organization_id=org_id,
        plugin_key="slack",
        name="Slack",
        config={"incoming_webhook_url": "https://hooks.slack.com/services/T123/B123/fake"},
    )
    db_session.add(instance)
    incident = Incident(organization_id=org_id, title="t", risk_level="high", risk_score=80, priority="high")
    db_session.add(incident)
    db_session.flush()
    assignee = User(organization_id=org_id, email="priya@example.com", hashed_password="x", role="analyst")
    db_session.add(assignee)
    db_session.commit()

    with patch("app.slack_bot.httpx.post") as mock_post:
        notify_assignment(db_session, incident, assignee)

    mock_post.assert_called_once()
    assert "priya@example.com" in mock_post.call_args.kwargs["json"]["text"]


def test_notify_status_change_posts_a_real_message(db_session, org_id):
    from app.db_models import User
    from app.slack_bot import notify_status_change

    instance = ConnectorInstance(
        organization_id=org_id,
        plugin_key="slack",
        name="Slack",
        config={"incoming_webhook_url": "https://hooks.slack.com/services/T123/B123/fake"},
    )
    db_session.add(instance)
    incident = Incident(organization_id=org_id, title="t", risk_level="high", risk_score=80, priority="high")
    db_session.add(incident)
    db_session.flush()
    actor = User(organization_id=org_id, email="admin@example.com", hashed_password="x", role="admin")
    db_session.add(actor)
    db_session.commit()

    with patch("app.slack_bot.httpx.post") as mock_post:
        notify_status_change(db_session, incident, actor, "open", "closed")

    mock_post.assert_called_once()
    posted_text = mock_post.call_args.kwargs["json"]["text"]
    assert "open" in posted_text and "closed" in posted_text


def test_notify_comment_posts_a_real_message(db_session, org_id):
    from app.db_models import User
    from app.slack_bot import notify_comment

    instance = ConnectorInstance(
        organization_id=org_id,
        plugin_key="slack",
        name="Slack",
        config={"incoming_webhook_url": "https://hooks.slack.com/services/T123/B123/fake"},
    )
    db_session.add(instance)
    incident = Incident(organization_id=org_id, title="t", risk_level="high", risk_score=80, priority="high")
    db_session.add(incident)
    db_session.flush()
    author = User(organization_id=org_id, email="priya@example.com", hashed_password="x", role="analyst")
    db_session.add(author)
    db_session.commit()

    with patch("app.slack_bot.httpx.post") as mock_post:
        notify_comment(db_session, incident, author, "This looks legitimate.")

    mock_post.assert_called_once()
    posted_text = mock_post.call_args.kwargs["json"]["text"]
    assert "priya@example.com" in posted_text
    assert "This looks legitimate." in posted_text


def test_notify_assignment_is_a_noop_without_connector(db_session, org_id):
    from app.db_models import User
    from app.slack_bot import notify_assignment

    incident = Incident(organization_id=org_id, title="t", risk_level="low", risk_score=10, priority="low")
    db_session.add(incident)
    db_session.flush()
    assignee = User(organization_id=org_id, email="x@example.com", hashed_password="x", role="analyst")
    db_session.add(assignee)
    db_session.commit()

    notify_assignment(db_session, incident, assignee)
