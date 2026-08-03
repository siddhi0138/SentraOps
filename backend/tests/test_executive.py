import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from app.ai import ChatConfigError, ChatProviderError
from app.executive import get_summary
from app.ingestion import ingest
from app.correlation import run_correlation

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"


def _ransomware_incident(db_session, org_id):
    ingest(db_session, org_id, "windows", json.loads((SAMPLES / "windows_events.json").read_text()))
    ingest(db_session, org_id, "firewall", json.loads((SAMPLES / "firewall.json").read_text()))
    ingest(db_session, org_id, "syslog", (SAMPLES / "syslog.log").read_text().splitlines())
    return run_correlation(db_session, org_id)[0]


def test_get_summary_with_no_incidents(db_session, org_id):
    summary = get_summary(db_session, org_id)

    assert summary["open_critical_incidents"] == 0
    assert summary["open_high_incidents"] == 0
    assert summary["pending_actions"] == 0
    assert summary["mean_time_to_close_hours"] is None
    assert summary["incident_trend"] == []
    assert summary["top_incidents"] == []
    # Global count, includes the migration-seeded demo indicator even with
    # zero activity in this org.
    assert summary["threat_indicators_tracked"] >= 1


def test_get_summary_counts_open_critical_incident(db_session, org_id):
    incident = _ransomware_incident(db_session, org_id)
    assert incident.risk_level == "critical"

    summary = get_summary(db_session, org_id)
    assert summary["open_critical_incidents"] == 1
    assert len(summary["top_incidents"]) == 1
    assert summary["top_incidents"][0]["id"] == incident.id


def test_get_summary_buckets_incident_into_todays_trend(db_session, org_id):
    _ransomware_incident(db_session, org_id)

    summary = get_summary(db_session, org_id)
    assert len(summary["incident_trend"]) == 1
    today = summary["incident_trend"][0]
    assert today["date"] == datetime.now(timezone.utc).date().isoformat()
    assert today["critical"] == 1


def test_get_summary_computes_mean_time_to_close(db_session, org_id):
    incident = _ransomware_incident(db_session, org_id)
    incident.status = "closed"
    incident.created_at = datetime.now(timezone.utc) - timedelta(hours=5)
    incident.closed_at = datetime.now(timezone.utc)
    db_session.commit()

    summary = get_summary(db_session, org_id)
    assert summary["mean_time_to_close_hours"] == 5.0
    assert summary["open_critical_incidents"] == 0  # closed, not open


def test_summary_is_scoped_to_organization(db_session, org_id):
    from app.db_models import Organization

    other_org = Organization(name="Other", slug="other-exec-org")
    db_session.add(other_org)
    db_session.commit()
    db_session.refresh(other_org)

    _ransomware_incident(db_session, org_id)

    own_summary = get_summary(db_session, org_id)
    other_summary = get_summary(db_session, other_org.id)
    assert own_summary["open_critical_incidents"] == 1
    assert other_summary["open_critical_incidents"] == 0


def test_executive_summary_endpoint(client, viewer_headers):
    response = client.get("/executive/summary", headers=viewer_headers)
    assert response.status_code == 200
    body = response.json()
    assert "open_critical_incidents" in body
    assert "incident_trend" in body


def test_executive_summary_requires_authentication(client):
    assert client.get("/executive/summary").status_code == 401


def test_executive_briefing_success(client, viewer_headers):
    fake_briefing = {
        "headline": "Security posture is stable",
        "summary": "No critical incidents are currently open.",
        "key_risks": [],
        "recommended_focus": "Continue routine monitoring.",
    }
    with patch("app.main.generate_briefing", return_value=fake_briefing):
        response = client.post("/executive/briefing", headers=viewer_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["briefing"] == fake_briefing
    assert "summary" in body  # the real aggregate stats, not the LLM's "summary" key


def test_executive_briefing_not_configured(client, viewer_headers):
    with patch("app.main.generate_briefing", side_effect=ChatConfigError("GROQ_API_KEY is not set")):
        response = client.post("/executive/briefing", headers=viewer_headers)
    assert response.status_code == 503


def test_executive_briefing_provider_error(client, viewer_headers):
    with patch("app.main.generate_briefing", side_effect=ChatProviderError("rate limited")):
        response = client.post("/executive/briefing", headers=viewer_headers)
    assert response.status_code == 502


def test_executive_briefing_requires_authentication(client):
    assert client.post("/executive/briefing").status_code == 401
