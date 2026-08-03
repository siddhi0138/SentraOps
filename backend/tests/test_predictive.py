from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from app.ai import ChatConfigError, ChatProviderError
from app.ingestion import ingest
from app.predictive import detect_anomalous_entities, privilege_escalation_trend, risk_drift


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def test_detect_anomalous_entities_insufficient_data_with_few_actors(db_session, org_id):
    ingest(db_session, org_id, "generic", [
        {"timestamp": "2026-07-24T09:00:00", "host": "HOST-A", "username": "alice", "source_ip": "1.1.1.1",
         "event_type": "login_success", "severity": "low", "message": "a"},
    ])
    result = detect_anomalous_entities(db_session, org_id)
    assert result["status"] == "insufficient_data"
    assert result["anomalies"] == []


def test_detect_anomalous_entities_flags_a_real_outlier(db_session, org_id):
    base = datetime(2026, 7, 1, 10, 0, tzinfo=timezone.utc)  # 10am - business hours
    events = []
    # Five "normal" actors: same host each day, one IP, all successful logins.
    for i in range(6):
        for day in range(5):
            events.append({
                "timestamp": _iso(base + timedelta(days=day, hours=i)),
                "host": f"HOST-{i}",
                "username": f"user{i}",
                "source_ip": "10.0.0.1",
                "event_type": "login_success",
                "severity": "low",
                "message": "normal login",
            })
    # One clear outlier: many distinct IPs, off-hours, mostly failed logins.
    for j in range(8):
        events.append({
            "timestamp": _iso(base.replace(hour=2) + timedelta(days=j)),  # 2am - off hours
            "host": "HOST-OUTLIER",
            "username": "outlier.user",
            "source_ip": f"203.0.113.{j}",
            "event_type": "login_failed",
            "severity": "high",
            "message": "failed login",
        })
    ingest(db_session, org_id, "generic", events)

    result = detect_anomalous_entities(db_session, org_id)
    assert result["status"] == "ok"
    assert result["entities_analyzed"] == 7
    flagged = {a["username"] for a in result["anomalies"]}
    assert "outlier.user" in flagged
    outlier = next(a for a in result["anomalies"] if a["username"] == "outlier.user")
    assert outlier["reasons"]


def test_privilege_escalation_trend_none_without_any_events(db_session, org_id):
    result = privilege_escalation_trend(db_session, org_id)
    assert result["direction"] == "none"
    assert result["total"] == 0


def test_privilege_escalation_trend_rising_with_increasing_daily_counts(db_session, org_id):
    now = datetime.now(timezone.utc)
    events = []
    for day, count in enumerate([1, 2, 3, 5, 8]):
        for i in range(count):
            ts = now - timedelta(days=4 - day, hours=i)
            events.append({
                "timestamp": _iso(ts),
                "host": "HOST-A",
                "username": "alice",
                "source_ip": "1.1.1.1",
                "event_type": "privilege_escalation",
                "severity": "high",
                "message": "priv esc",
            })
    ingest(db_session, org_id, "generic", events)

    result = privilege_escalation_trend(db_session, org_id)
    assert result["direction"] == "rising"
    assert result["total"] == 19


def test_risk_drift_insufficient_data_with_fewer_than_two_incidents(db_session, org_id):
    result = risk_drift(db_session, org_id)
    assert result["direction"] == "insufficient_data"


def test_risk_drift_worsening_when_recent_incidents_score_higher(db_session, org_id):
    from app.db_models import Incident

    now = datetime.now(timezone.utc)
    for i, score in enumerate([10, 15, 20, 80, 90]):
        db_session.add(
            Incident(
                organization_id=org_id,
                title=f"Incident {i}",
                confidence=50,
                risk_score=score,
                risk_level="low",
                created_at=now - timedelta(days=5 - i),
            )
        )
    db_session.commit()

    result = risk_drift(db_session, org_id, window=2)
    assert result["direction"] == "worsening"
    assert result["recent_average"] > result["prior_average"]


def test_predictive_summary_endpoint(client, viewer_headers):
    response = client.get("/predictive/summary", headers=viewer_headers)
    assert response.status_code == 200
    body = response.json()
    assert set(body.keys()) == {"anomalous_entities", "privilege_escalation_trend", "risk_drift"}


def test_predictive_summary_requires_authentication(client):
    assert client.get("/predictive/summary").status_code == 401


def test_predictive_briefing_success(client, viewer_headers):
    fake_briefing = {
        "headline": "Predictive risk is low.",
        "summary": "No significant signals detected.",
        "likely_scenarios": [],
        "recommended_watch": "Continue routine monitoring.",
    }
    with patch("app.main.generate_predictive_briefing", return_value=fake_briefing):
        response = client.post("/predictive/briefing", headers=viewer_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["briefing"] == fake_briefing
    assert "summary" in body


def test_predictive_briefing_not_configured(client, viewer_headers):
    with patch("app.main.generate_predictive_briefing", side_effect=ChatConfigError("GROQ_API_KEY is not set")):
        response = client.post("/predictive/briefing", headers=viewer_headers)
    assert response.status_code == 503


def test_predictive_briefing_provider_error(client, viewer_headers):
    with patch("app.main.generate_predictive_briefing", side_effect=ChatProviderError("rate limited")):
        response = client.post("/predictive/briefing", headers=viewer_headers)
    assert response.status_code == 502


def test_predictive_briefing_requires_authentication(client):
    assert client.post("/predictive/briefing").status_code == 401
