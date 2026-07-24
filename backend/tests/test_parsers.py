import json
from pathlib import Path

import pytest

from app.parsers import cloudtrail, firewall, generic, syslog, webserver, windows
from app.parsers import get_parser

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"


def test_registry_returns_parser_by_source_type():
    assert get_parser("windows") is windows.parse
    with pytest.raises(ValueError):
        get_parser("does_not_exist")


def test_windows_parser_maps_failed_logon():
    events = json.loads((SAMPLES / "windows_events.json").read_text())
    parsed = windows.parse(events[0])
    assert parsed["event_type"] == "login_failed"
    assert parsed["severity"] == "medium"
    assert parsed["username"] == "j.mehta"
    assert parsed["source_ip"] == "185.220.101.45"


def test_windows_parser_flags_encoded_powershell_as_high():
    events = json.loads((SAMPLES / "windows_events.json").read_text())
    powershell_event = next(e for e in events if e["EventID"] == 4688)
    parsed = windows.parse(powershell_event)
    assert parsed["event_type"] == "process_execution"
    assert parsed["severity"] == "high"


def test_windows_parser_flags_shadow_copy_deletion_as_critical():
    parsed = windows.parse({
        "EventID": 4688,
        "Computer": "FINANCE-PC-21",
        "SubjectUserName": "svc_update",
        "CommandLine": "vssadmin.exe delete shadows /all /quiet",
        "TimeCreated": "2026-07-24T09:33:12Z",
    })
    assert parsed["event_type"] == "process_execution"
    assert parsed["severity"] == "critical"


def test_windows_parser_maps_account_creation_to_privilege_escalation():
    events = json.loads((SAMPLES / "windows_events.json").read_text())
    account_event = next(e for e in events if e["EventID"] == 4720)
    parsed = windows.parse(account_event)
    assert parsed["event_type"] == "privilege_escalation"
    assert parsed["severity"] == "high"


def test_syslog_parser_detects_failed_password():
    lines = (SAMPLES / "syslog.log").read_text().splitlines()
    parsed = syslog.parse(lines[0])
    assert parsed["event_type"] == "login_failed"
    assert parsed["source_ip"] == "185.220.101.45"


def test_syslog_parser_detects_sudo_command():
    lines = (SAMPLES / "syslog.log").read_text().splitlines()
    sudo_line = next(line for line in lines if "COMMAND=" in line)
    parsed = syslog.parse(sudo_line)
    assert parsed["event_type"] == "privilege_escalation"
    assert parsed["username"] == "svc_update"


def test_syslog_parser_rejects_unrecognized_line():
    with pytest.raises(ValueError):
        syslog.parse("this is not a syslog line at all")


def test_webserver_parser_flags_401_as_auth_failed():
    lines = (SAMPLES / "access.log").read_text().splitlines()
    unauthorized = next(line for line in lines if " 401 " in line)
    parsed = webserver.parse(unauthorized)
    assert parsed["event_type"] == "auth_failed"
    assert parsed["source_ip"] == "185.220.101.45"


def test_webserver_parser_flags_500_as_high_severity():
    lines = (SAMPLES / "access.log").read_text().splitlines()
    server_error = next(line for line in lines if " 500 " in line)
    parsed = webserver.parse(server_error)
    assert parsed["event_type"] == "http_error"
    assert parsed["severity"] == "high"


def test_firewall_parser_deny_vs_allow():
    entries = json.loads((SAMPLES / "firewall.json").read_text())
    deny = next(e for e in entries if e["action"] == "DENY")
    allow = next(e for e in entries if e["action"] == "ALLOW")
    assert firewall.parse(deny)["event_type"] == "firewall_deny"
    assert firewall.parse(allow)["event_type"] == "firewall_allow"


def test_cloudtrail_parser_flags_privilege_escalation():
    entries = json.loads((SAMPLES / "cloudtrail.json").read_text())
    create_user = next(e for e in entries if e["eventName"] == "CreateUser")
    parsed = cloudtrail.parse(create_user)
    assert parsed["event_type"] == "privilege_escalation"
    assert parsed["severity"] == "high"


def test_cloudtrail_parser_console_login_success():
    entries = json.loads((SAMPLES / "cloudtrail.json").read_text())
    login = next(e for e in entries if e["eventName"] == "ConsoleLogin")
    parsed = cloudtrail.parse(login)
    assert parsed["event_type"] == "login_success"


def test_generic_parser_passes_through_legacy_fields():
    parsed = generic.parse({
        "timestamp": "2026-07-24T09:29:44",
        "host": "DB-SERVER-03",
        "user": "svc_update",
        "event_type": "data_transfer",
        "detail": "2.3 GB exported from customers.db",
        "source_ip": "185.220.101.45",
    })
    assert parsed["username"] == "svc_update"
    assert parsed["message"] == "2.3 GB exported from customers.db"
    assert parsed["severity"] == "high"
