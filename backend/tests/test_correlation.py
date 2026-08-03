import json
from pathlib import Path

from app.correlation import run_correlation
from app.db_models import Event
from app.ingestion import ingest

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"


def _ingest_ransomware_scenario(db_session, org_id):
    ingest(db_session, org_id, "windows", json.loads((SAMPLES / "windows_events.json").read_text()))
    ingest(db_session, org_id, "firewall", json.loads((SAMPLES / "firewall.json").read_text()))
    ingest(db_session, org_id, "syslog", (SAMPLES / "syslog.log").read_text().splitlines())


def test_correlation_groups_related_events_into_one_incident(db_session, org_id):
    _ingest_ransomware_scenario(db_session, org_id)
    total_events = db_session.query(Event).count()

    incidents = run_correlation(db_session, org_id)

    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.risk_level == "critical"
    assert incident.confidence == 96
    assert len(incident.events) == total_events
    assert "FINANCE-PC-21" in incident.affected_hosts


def test_correlation_flags_threat_intel_match(db_session, org_id):
    _ingest_ransomware_scenario(db_session, org_id)
    incident = run_correlation(db_session, org_id)[0]

    assert any(ti["indicator"] == "185.220.101.45" for ti in incident.threat_intel)


def test_correlation_recommends_containment_actions(db_session, org_id):
    _ingest_ransomware_scenario(db_session, org_id)
    incident = run_correlation(db_session, org_id)[0]

    actions_text = " ".join(incident.recommended_actions)
    assert "Isolate host" in actions_text
    assert "Block source IP" in actions_text
    assert "backups" in actions_text  # critical severity => ransomware warning


def test_correlation_is_idempotent_for_already_correlated_events(db_session, org_id):
    _ingest_ransomware_scenario(db_session, org_id)
    first_run = run_correlation(db_session, org_id)
    assert len(first_run) == 1

    second_run = run_correlation(db_session, org_id)
    assert second_run == []


def test_correlation_keeps_unrelated_alerts_as_separate_incidents(db_session, org_id):
    ingest(db_session, org_id, "generic", [
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

    incidents = run_correlation(db_session, org_id)
    assert len(incidents) == 2


def test_bridging_event_is_claimed_by_exactly_one_incident(db_session, org_id):
    """A low-severity event can match two unrelated clusters' identity sets at
    once (shares a host with one, a username with the other). It must end up
    in exactly one incident's persisted timeline, and that incident's report
    must be the one that actually describes it - not the other way around."""
    ingest(db_session, org_id, "generic", [
        {"timestamp": "2026-07-24T09:00:00", "host": "HOST-A", "username": "alice", "event_type": "privilege_escalation", "severity": "high", "message": "a1"},
        {"timestamp": "2026-07-24T09:05:00", "host": "HOST-B", "username": "bob", "event_type": "privilege_escalation", "severity": "high", "message": "b1"},
        {"timestamp": "2026-07-24T09:10:00", "host": "HOST-A", "username": "bob", "event_type": "login_success", "severity": "low", "message": "bridge"},
    ])

    incidents = run_correlation(db_session, org_id)

    assert len(incidents) == 2
    assert sum(len(i.events) for i in incidents) == 3  # no event dropped or double-claimed

    for incident in incidents:
        mentions_bridge_in_report = "bridge" in incident.report
        has_bridge_in_events = any(e.message == "bridge" for e in incident.events)
        assert mentions_bridge_in_report == has_bridge_in_events


def test_correlation_ignores_low_severity_only_activity(db_session, org_id):
    ingest(db_session, org_id, "generic", [{
        "timestamp": "2026-07-24T10:00:00",
        "host": "HOST-A",
        "username": "alice",
        "event_type": "login_success",
        "severity": "low",
        "message": "normal login",
    }])

    incidents = run_correlation(db_session, org_id)
    assert incidents == []


def test_correlation_does_not_cluster_events_across_organizations(db_session, org_id):
    """Two different tenants' events that share a host/user/IP must never
    be merged into the same incident - a correlation-level cross-tenant
    leak would be worse than a query-level one."""
    from app.db_models import Organization

    other_org = Organization(name="Other Org", slug="other-org")
    db_session.add(other_org)
    db_session.commit()
    db_session.refresh(other_org)

    shared_event = {
        "timestamp": "2026-07-24T10:00:00",
        "host": "SHARED-HOST",
        "username": "shared-user",
        "source_ip": "9.9.9.9",
        "event_type": "privilege_escalation",
        "severity": "high",
        "message": "org A event",
    }
    ingest(db_session, org_id, "generic", [shared_event])
    ingest(db_session, other_org.id, "generic", [{**shared_event, "message": "org B event"}])

    incidents_a = run_correlation(db_session, org_id)
    incidents_b = run_correlation(db_session, other_org.id)

    assert len(incidents_a) == 1
    assert len(incidents_b) == 1
    assert incidents_a[0].id != incidents_b[0].id
    assert len(incidents_a[0].events) == 1
    assert len(incidents_b[0].events) == 1
