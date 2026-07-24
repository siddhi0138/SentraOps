import json
from pathlib import Path

from app.correlation import run_correlation
from app.db_models import Event
from app.ingestion import ingest

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"


def _ingest_ransomware_scenario(db_session):
    ingest(db_session, "windows", json.loads((SAMPLES / "windows_events.json").read_text()))
    ingest(db_session, "firewall", json.loads((SAMPLES / "firewall.json").read_text()))
    ingest(db_session, "syslog", (SAMPLES / "syslog.log").read_text().splitlines())


def test_correlation_groups_related_events_into_one_incident(db_session):
    _ingest_ransomware_scenario(db_session)
    total_events = db_session.query(Event).count()

    incidents = run_correlation(db_session)

    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.risk_level == "critical"
    assert incident.confidence == 96
    assert len(incident.events) == total_events
    assert "FINANCE-PC-21" in incident.affected_hosts


def test_correlation_flags_threat_intel_match(db_session):
    _ingest_ransomware_scenario(db_session)
    incident = run_correlation(db_session)[0]

    assert any(ti["indicator"] == "185.220.101.45" for ti in incident.threat_intel)


def test_correlation_recommends_containment_actions(db_session):
    _ingest_ransomware_scenario(db_session)
    incident = run_correlation(db_session)[0]

    actions_text = " ".join(incident.recommended_actions)
    assert "Isolate host" in actions_text
    assert "Block source IP" in actions_text
    assert "backups" in actions_text  # critical severity => ransomware warning


def test_correlation_is_idempotent_for_already_correlated_events(db_session):
    _ingest_ransomware_scenario(db_session)
    first_run = run_correlation(db_session)
    assert len(first_run) == 1

    second_run = run_correlation(db_session)
    assert second_run == []


def test_correlation_keeps_unrelated_alerts_as_separate_incidents(db_session):
    ingest(db_session, "generic", [
        {
            "timestamp": "2026-07-24T10:00:00",
            "host": "HOST-A",
            "username": "alice",
            "source_ip": "1.1.1.1",
            "event_type": "privilege_escalation",
            "severity": "high",
            "message": "alice incident",
        },
        {
            "timestamp": "2026-07-24T11:00:00",
            "host": "HOST-B",
            "username": "bob",
            "source_ip": "2.2.2.2",
            "event_type": "privilege_escalation",
            "severity": "high",
            "message": "bob incident",
        },
    ])

    incidents = run_correlation(db_session)
    assert len(incidents) == 2


def test_correlation_ignores_low_severity_only_activity(db_session):
    ingest(db_session, "generic", [{
        "timestamp": "2026-07-24T10:00:00",
        "host": "HOST-A",
        "username": "alice",
        "event_type": "login_success",
        "severity": "low",
        "message": "normal login",
    }])

    incidents = run_correlation(db_session)
    assert incidents == []
