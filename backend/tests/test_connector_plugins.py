from unittest.mock import patch

import httpx

from app.plugins.actions.jira import JiraAction
from app.plugins.actions.servicenow import ServiceNowAction
from app.plugins.actions.webhook import WebhookAction
from app.plugins.connectors.generic_rest import GenericRestConnector
from app.plugins.connectors.github_events import GitHubEventsConnector
from app.plugins.connectors.urlhaus import UrlhausConnector


def _response(url: str, status_code: int, text: str = "", json_body=None) -> httpx.Response:
    request = httpx.Request("GET", url)
    if json_body is not None:
        return httpx.Response(status_code, json=json_body, request=request)
    return httpx.Response(status_code, text=text, request=request)


SAMPLE_URLHAUS_CSV = (
    "################################################################\n"
    "# abuse.ch URLhaus Database Dump\n"
    "################################################################\n"
    "#\n"
    "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
    '"111","2026-07-26 18:41:26","http://182.127.55.197:36002/i","online","2026-07-26 18:41:26",'
    '"malware_download","32-bit,elf,mips,Mozi","https://urlhaus.abuse.ch/url/111/","reporterA"\n'
    '"112","2026-07-26 18:38:19","http://5.182.210.61/1da144","offline","",'
    '"malware_download","ua-wget","https://urlhaus.abuse.ch/url/112/","abuse_ch"\n'
)


def test_urlhaus_pull_parses_csv_and_maps_severity():
    connector = UrlhausConnector()
    with patch("app.plugins.connectors.urlhaus.httpx.get", return_value=_response(
        "https://urlhaus.abuse.ch/downloads/csv_recent/", 200, text=SAMPLE_URLHAUS_CSV
    )):
        items = connector.pull({})

    assert len(items) == 2
    assert items[0]["host"] == "182.127.55.197"
    assert items[0]["severity"] == "high"  # url_status=online
    assert items[0]["event_type"] == "malicious_url_reported"
    assert items[1]["host"] == "5.182.210.61"
    assert items[1]["severity"] == "medium"  # url_status=offline


def test_urlhaus_test_connection_success():
    connector = UrlhausConnector()
    with patch("app.plugins.connectors.urlhaus.httpx.get", return_value=_response(
        "https://urlhaus.abuse.ch/downloads/csv_recent/", 200, text=SAMPLE_URLHAUS_CSV
    )):
        ok, message = connector.test_connection({})
    assert ok is True


def test_urlhaus_test_connection_failure_on_network_error():
    connector = UrlhausConnector()
    with patch("app.plugins.connectors.urlhaus.httpx.get", side_effect=httpx.ConnectError("boom")):
        ok, message = connector.test_connection({})
    assert ok is False
    assert "boom" in message


def test_github_events_requires_owner_slash_name():
    connector = GitHubEventsConnector()
    ok, message = connector.test_connection({"repo": "not-a-valid-repo-format"})
    assert ok is False


def test_github_events_test_connection_404():
    connector = GitHubEventsConnector()
    with patch("app.plugins.connectors.github_events.httpx.get", return_value=_response(
        "https://api.github.com/repos/foo/bar", 404
    )):
        ok, message = connector.test_connection({"repo": "foo/bar"})
    assert ok is False
    assert "not found" in message.lower()


def test_github_events_pull_maps_event_severity():
    connector = GitHubEventsConnector()
    fake_events = [
        {"type": "MemberEvent", "created_at": "2026-07-27T00:00:00Z", "actor": {"login": "alice"}},
        {"type": "PushEvent", "created_at": "2026-07-27T00:01:00Z", "actor": {"login": "bob"}},
    ]
    with patch("app.plugins.connectors.github_events.httpx.get", return_value=_response(
        "https://api.github.com/repos/foo/bar/events", 200, json_body=fake_events
    )):
        items = connector.pull({"repo": "foo/bar"})

    assert len(items) == 2
    assert items[0]["severity"] == "high"  # MemberEvent
    assert items[0]["username"] == "alice"
    assert items[1]["severity"] == "low"  # PushEvent falls back to low
    assert items[1]["host"] == "foo/bar"


def test_webhook_action_requires_url():
    ok, message = WebhookAction().execute({}, {"category": "containment", "incident_id": 1, "description": "x"})
    assert ok is False


def test_webhook_action_posts_and_reports_success():
    action = {"category": "containment", "incident_id": 7, "description": "Disable account x"}
    with patch("app.plugins.actions.webhook.httpx.post", return_value=_response("https://example.com/hook", 200)):
        ok, message = WebhookAction().execute({"webhook_url": "https://example.com/hook"}, action)
    assert ok is True


def test_webhook_action_reports_http_failure():
    action = {"category": "containment", "incident_id": 7, "description": "Disable account x"}
    with patch("app.plugins.actions.webhook.httpx.post", side_effect=httpx.ConnectError("unreachable")):
        ok, message = WebhookAction().execute({"webhook_url": "https://example.com/hook"}, action)
    assert ok is False
    assert "unreachable" in message


GENERIC_REST_CONFIG = {
    "base_url": "https://vendor.example.com/api/events",
    "auth_header_name": "X-Api-Key",
    "auth_header_value": "secret-key",
    "events_json_path": "data.items",
    "field_map": (
        '{"timestamp": "occurred_at", "host": "asset.hostname", "username": "actor", '
        '"source_ip": "src_ip", "event_type": "type", "severity": "level", "message": "summary"}'
    ),
    "severity_map": '{"warn": "medium", "crit": "critical"}',
}

VENDOR_SHAPED_RESPONSE = {
    "data": {
        "items": [
            {
                "occurred_at": "2026-07-24T09:16:40Z",
                "asset": {"hostname": "FINANCE-PC-21"},
                "actor": "j.mehta",
                "src_ip": "185.220.101.45",
                "type": "login_failed",
                "level": "warn",
                "summary": "Failed login attempt",
            },
            "not-a-dict-should-be-skipped",
            {
                "occurred_at": "2026-07-24T09:20:00Z",
                "asset": {"hostname": "DB-SERVER-03"},
                "type": "process_execution",
                "level": "crit",
                "summary": "Suspicious process launched",
            },
        ]
    }
}


def test_generic_rest_pull_maps_vendor_fields_via_field_map():
    connector = GenericRestConnector()
    with patch(
        "app.plugins.connectors.generic_rest.httpx.get",
        return_value=_response(GENERIC_REST_CONFIG["base_url"], 200, json_body=VENDOR_SHAPED_RESPONSE),
    ):
        items = connector.pull(GENERIC_REST_CONFIG)

    assert len(items) == 2  # the non-dict entry is skipped, not crashed on
    first = items[0]
    assert first["host"] == "FINANCE-PC-21"
    assert first["username"] == "j.mehta"
    assert first["source_ip"] == "185.220.101.45"
    assert first["event_type"] == "login_failed"
    assert first["severity"] == "medium"  # "warn" -> "medium" via severity_map
    assert first["message"] == "Failed login attempt"

    second = items[1]
    assert second["host"] == "DB-SERVER-03"
    assert second["username"] is None  # vendor payload has no "actor" field for this item
    assert second["severity"] == "critical"  # "crit" -> "critical" via severity_map


def test_generic_rest_pull_falls_back_to_raw_severity_when_unmapped_and_unrecognized():
    config = {**GENERIC_REST_CONFIG, "severity_map": ""}
    response_body = {"data": {"items": [{**VENDOR_SHAPED_RESPONSE["data"]["items"][0], "level": "totally-unknown"}]}}
    connector = GenericRestConnector()
    with patch("app.plugins.connectors.generic_rest.httpx.get", return_value=_response(GENERIC_REST_CONFIG["base_url"], 200, json_body=response_body)):
        items = connector.pull(config)
    assert items[0]["severity"] == "medium"  # unrecognized raw value falls back to the default, not left as garbage


def test_generic_rest_pull_treats_unmapped_field_as_none_not_whole_item():
    # Caught live against a real public API: mapping "source_ip" to an
    # empty/absent field_map entry once returned the *entire raw item* as
    # source_ip, because the same _get_path() helper used for
    # events_json_path treats an empty path as "return the whole thing" -
    # correct there (an unwrapped top-level array), wrong for a single
    # unmapped field, which must mean "not provided".
    config = {**GENERIC_REST_CONFIG, "field_map": '{"host": "asset.hostname"}'}
    response_body = {"data": {"items": [VENDOR_SHAPED_RESPONSE["data"]["items"][0]]}}
    connector = GenericRestConnector()
    with patch("app.plugins.connectors.generic_rest.httpx.get", return_value=_response(GENERIC_REST_CONFIG["base_url"], 200, json_body=response_body)):
        items = connector.pull(config)
    assert items[0]["host"] == "FINANCE-PC-21"
    assert items[0]["source_ip"] is None
    assert items[0]["username"] is None
    assert items[0]["message"] is None or isinstance(items[0]["message"], str)
    assert not isinstance(items[0]["source_ip"], dict)


def test_generic_rest_pull_requires_base_url():
    try:
        GenericRestConnector().pull({})
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_generic_rest_pull_rejects_non_list_events_path():
    connector = GenericRestConnector()
    with patch(
        "app.plugins.connectors.generic_rest.httpx.get",
        return_value=_response(GENERIC_REST_CONFIG["base_url"], 200, json_body={"data": {"items": "not-a-list"}}),
    ):
        try:
            connector.pull(GENERIC_REST_CONFIG)
            assert False, "expected ValueError"
        except ValueError:
            pass


def test_generic_rest_test_connection_sends_configured_auth_header():
    connector = GenericRestConnector()
    with patch("app.plugins.connectors.generic_rest.httpx.get", return_value=_response(GENERIC_REST_CONFIG["base_url"], 200)) as mock_get:
        ok, message = connector.test_connection(GENERIC_REST_CONFIG)
    assert ok is True
    _, kwargs = mock_get.call_args
    assert kwargs["headers"]["X-Api-Key"] == "secret-key"


def test_generic_rest_test_connection_reports_http_error_status():
    connector = GenericRestConnector()
    with patch("app.plugins.connectors.generic_rest.httpx.get", return_value=_response(GENERIC_REST_CONFIG["base_url"], 401)):
        ok, message = connector.test_connection(GENERIC_REST_CONFIG)
    assert ok is False
    assert "401" in message


def test_generic_rest_test_connection_requires_base_url():
    ok, message = GenericRestConnector().test_connection({})
    assert ok is False


JIRA_CONFIG = {
    "base_url": "https://acme.atlassian.net",
    "email": "admin@acme.com",
    "api_token": "fake-token",
    "project_key": "SEC",
}


def test_jira_action_requires_full_config():
    ok, message = JiraAction().execute({}, {"category": "containment", "incident_id": 1, "description": "x"})
    assert ok is False
    assert "required" in message


def test_jira_action_creates_issue_and_reports_key():
    action = {"category": "containment", "incident_id": 7, "description": "Isolate FINANCE-PC-21"}
    with patch(
        "app.plugins.actions.jira.httpx.post",
        return_value=_response(f"{JIRA_CONFIG['base_url']}/rest/api/3/issue", 201, json_body={"key": "SEC-142"}),
    ) as mock_post:
        ok, message = JiraAction().execute(JIRA_CONFIG, action)

    assert ok is True
    assert "SEC-142" in message
    call_kwargs = mock_post.call_args.kwargs
    assert call_kwargs["auth"] == (JIRA_CONFIG["email"], JIRA_CONFIG["api_token"])
    assert call_kwargs["json"]["fields"]["project"]["key"] == "SEC"


def test_jira_action_reports_http_failure():
    action = {"category": "containment", "incident_id": 7, "description": "x"}
    with patch("app.plugins.actions.jira.httpx.post", side_effect=httpx.ConnectError("unreachable")):
        ok, message = JiraAction().execute(JIRA_CONFIG, action)
    assert ok is False
    assert "unreachable" in message


SERVICENOW_CONFIG = {
    "instance_url": "https://acmedev.service-now.com",
    "username": "admin",
    "password": "fake-password",
}


def test_servicenow_action_requires_full_config():
    ok, message = ServiceNowAction().execute({}, {"category": "containment", "incident_id": 1, "description": "x"})
    assert ok is False
    assert "required" in message


def test_servicenow_action_creates_incident_and_reports_number():
    action = {"category": "eradication", "incident_id": 9, "description": "Reset compromised credentials"}
    with patch(
        "app.plugins.actions.servicenow.httpx.post",
        return_value=_response(
            f"{SERVICENOW_CONFIG['instance_url']}/api/now/table/incident", 201, json_body={"result": {"number": "INC0012345"}}
        ),
    ) as mock_post:
        ok, message = ServiceNowAction().execute(SERVICENOW_CONFIG, action)

    assert ok is True
    assert "INC0012345" in message
    call_kwargs = mock_post.call_args.kwargs
    assert call_kwargs["auth"] == (SERVICENOW_CONFIG["username"], SERVICENOW_CONFIG["password"])
    assert call_kwargs["json"]["urgency"] == "2"


def test_servicenow_action_reports_http_failure():
    action = {"category": "containment", "incident_id": 7, "description": "x"}
    with patch("app.plugins.actions.servicenow.httpx.post", side_effect=httpx.ConnectError("unreachable")):
        ok, message = ServiceNowAction().execute(SERVICENOW_CONFIG, action)
    assert ok is False
    assert "unreachable" in message
