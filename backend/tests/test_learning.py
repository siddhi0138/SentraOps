from datetime import datetime, timedelta, timezone

from app.agents.memory import build_memory_context
from app.agents.state import format_memory_context
from app.correlation import run_correlation
from app.db_models import AnalystFeedback, Incident, ProposedAction, User
from app.learning import get_evaluation_summary, get_feedback_stats, get_recent_corrections, record_feedback
from tests.test_agent_memory import _create_incident_sharing_host, _run_investigation


def _incident(db_session, org_id, title="t") -> Incident:
    incident = Incident(organization_id=org_id, title=title, report="r")
    db_session.add(incident)
    db_session.commit()
    db_session.refresh(incident)
    return incident


def _user(db_session, org_id, email="reviewer@example.com") -> User:
    from app.auth import hash_password

    user = User(organization_id=org_id, email=email, hashed_password=hash_password("x"), role="analyst")
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def test_record_and_list_feedback(db_session, org_id):
    incident = _incident(db_session, org_id)
    user = _user(db_session, org_id)

    feedback = record_feedback(db_session, org_id, incident.id, "accurate", "Correctly identified.", user.id)
    assert feedback.id is not None
    assert feedback.reviewed_by_id == user.id


def test_feedback_stats_counts_and_accuracy_rate(db_session, org_id):
    incident = _incident(db_session, org_id)
    user = _user(db_session, org_id)

    record_feedback(db_session, org_id, incident.id, "accurate", None, user.id)
    record_feedback(db_session, org_id, incident.id, "accurate", None, user.id)
    record_feedback(db_session, org_id, incident.id, "false_positive", "Not really malicious.", user.id)

    stats = get_feedback_stats(db_session, org_id)
    assert stats["total_feedback"] == 3
    assert stats["counts"] == {"accurate": 2, "false_positive": 1, "missed_detection": 0}
    assert stats["accuracy_rate"] == round(2 / 3 * 100, 1)


def test_feedback_stats_with_no_feedback(db_session, org_id):
    stats = get_feedback_stats(db_session, org_id)
    assert stats["total_feedback"] == 0
    assert stats["accuracy_rate"] is None
    assert stats["trend"] == []


def test_feedback_stats_buckets_into_todays_trend(db_session, org_id):
    incident = _incident(db_session, org_id)
    user = _user(db_session, org_id)
    record_feedback(db_session, org_id, incident.id, "accurate", None, user.id)

    stats = get_feedback_stats(db_session, org_id)
    assert len(stats["trend"]) == 1
    assert stats["trend"][0]["date"] == datetime.now(timezone.utc).date().isoformat()
    assert stats["trend"][0]["accurate"] == 1


def test_feedback_stats_excludes_old_entries_outside_trend_window(db_session, org_id):
    incident = _incident(db_session, org_id)
    user = _user(db_session, org_id)
    old = record_feedback(db_session, org_id, incident.id, "accurate", None, user.id)
    old.created_at = datetime.now(timezone.utc) - timedelta(days=60)
    db_session.commit()

    stats = get_feedback_stats(db_session, org_id)
    assert stats["total_feedback"] == 1  # counts/accuracy are all-time
    assert stats["trend"] == []  # but trend only covers the last 30 days


def test_recent_corrections_excludes_accurate_and_notes_missing(db_session, org_id):
    incident = _incident(db_session, org_id)
    user = _user(db_session, org_id)
    record_feedback(db_session, org_id, incident.id, "accurate", "Good catch.", user.id)
    record_feedback(db_session, org_id, incident.id, "false_positive", None, user.id)  # no note - excluded
    record_feedback(db_session, org_id, incident.id, "false_positive", "This was routine maintenance.", user.id)
    record_feedback(db_session, org_id, incident.id, "missed_detection", "Should have flagged the lateral movement.", user.id)

    corrections = get_recent_corrections(db_session, org_id)
    assert len(corrections) == 2
    assert {c["rating"] for c in corrections} == {"false_positive", "missed_detection"}
    assert all(c["note"] for c in corrections)


def test_recent_corrections_scoped_to_organization(db_session, org_id):
    from app.db_models import Organization

    other_org = Organization(name="Other", slug="other-learning-org")
    db_session.add(other_org)
    db_session.commit()
    db_session.refresh(other_org)

    incident = _incident(db_session, other_org.id)
    user = _user(db_session, other_org.id, email="other@example.com")
    record_feedback(db_session, other_org.id, incident.id, "false_positive", "Not ours.", user.id)

    assert get_recent_corrections(db_session, org_id) == []


def test_build_memory_context_includes_recent_corrections(db_session, org_id):
    incident = _incident(db_session, org_id)
    user = _user(db_session, org_id)
    record_feedback(db_session, org_id, incident.id, "missed_detection", "Watch for this pattern next time.", user.id)

    memory = build_memory_context(db_session, incident)
    assert len(memory["recent_corrections"]) == 1
    assert "Watch for this pattern next time." in format_memory_context(memory)


def test_investigation_passes_feedback_context_to_detection_agent(client, analyst_headers):
    incident_1_id, incident_2_id = _create_incident_sharing_host(client, analyst_headers)
    client.post(
        f"/incidents/{incident_1_id}/feedback",
        json={"rating": "false_positive", "note": "This turned out to be routine VPN maintenance."},
        headers=analyst_headers,
    )

    captured = {}

    def capture_detection(system_prompt, user_content, **kwargs):
        captured["detection"] = user_content
        from tests.test_agents_coordinator import FAKE_DETECTION

        return FAKE_DETECTION

    response = _run_investigation(client, analyst_headers, incident_2_id, detection_side_effect=capture_detection)
    assert response.status_code == 200
    assert "routine vpn maintenance" in captured["detection"].lower()


def test_create_incident_feedback_endpoint(client, analyst_headers):
    client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    client.post("/correlate", headers=analyst_headers)
    incident_id = client.get("/incidents", headers=analyst_headers).json()["incidents"][0]["id"]

    response = client.post(
        f"/incidents/{incident_id}/feedback",
        json={"rating": "accurate", "note": "Confirmed real ransomware."},
        headers=analyst_headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["rating"] == "accurate"
    assert body["reviewed_by_email"]

    listing = client.get(f"/incidents/{incident_id}/feedback", headers=analyst_headers)
    assert listing.status_code == 200
    assert len(listing.json()["feedback"]) == 1


def test_viewer_cannot_submit_feedback_but_can_read(client, analyst_headers, viewer_headers):
    client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    client.post("/correlate", headers=analyst_headers)
    incident_id = client.get("/incidents", headers=analyst_headers).json()["incidents"][0]["id"]

    assert (
        client.post(f"/incidents/{incident_id}/feedback", json={"rating": "accurate"}, headers=viewer_headers).status_code
        == 403
    )
    assert client.get(f"/incidents/{incident_id}/feedback", headers=viewer_headers).status_code == 200


def test_feedback_rejects_invalid_rating(client, analyst_headers):
    client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    client.post("/correlate", headers=analyst_headers)
    incident_id = client.get("/incidents", headers=analyst_headers).json()["incidents"][0]["id"]

    response = client.post(f"/incidents/{incident_id}/feedback", json={"rating": "maybe"}, headers=analyst_headers)
    assert response.status_code == 422


def test_feedback_unknown_incident_returns_404(client, analyst_headers):
    response = client.post("/incidents/99999/feedback", json={"rating": "accurate"}, headers=analyst_headers)
    assert response.status_code == 404


def test_feedback_requires_authentication(client):
    assert client.post("/incidents/1/feedback", json={"rating": "accurate"}).status_code == 401
    assert client.get("/incidents/1/feedback").status_code == 401


def test_learning_stats_endpoint(client, analyst_headers):
    client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    client.post("/correlate", headers=analyst_headers)
    incident_id = client.get("/incidents", headers=analyst_headers).json()["incidents"][0]["id"]
    client.post(f"/incidents/{incident_id}/feedback", json={"rating": "accurate"}, headers=analyst_headers)

    response = client.get("/learning/stats", headers=analyst_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["total_feedback"] == 1
    assert body["accuracy_rate"] == 100.0


def test_learning_stats_requires_authentication(client):
    assert client.get("/learning/stats").status_code == 401


def test_evaluation_summary_with_no_runs(db_session, org_id):
    summary = get_evaluation_summary(db_session, org_id)
    assert summary["total_investigations"] == 0
    assert summary["avg_investigation_duration_seconds"] is None
    assert summary["human_override_rate_pct"] is None
    for rating in ("accurate", "false_positive", "missed_detection"):
        assert summary["accuracy_correlation"][rating]["rated_investigations"] == 0


def test_evaluation_summary_computes_real_duration_from_a_real_investigation(client, analyst_headers, db_session):
    # org_id comes from /auth/me, not the separate org_id fixture - both
    # independently create a "Test Org" row and collide on the unique slug
    # if used together in the same test.
    org_id = client.get("/auth/me", headers=analyst_headers).json()["organization_id"]
    client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    client.post("/correlate", headers=analyst_headers)
    incident_id = client.get("/incidents", headers=analyst_headers).json()["incidents"][0]["id"]
    _run_investigation(client, analyst_headers, incident_id)

    summary = get_evaluation_summary(db_session, org_id)
    assert summary["total_investigations"] == 1
    assert summary["avg_investigation_duration_seconds"] is not None
    assert summary["avg_investigation_duration_seconds"] >= 0


def test_evaluation_summary_correlates_feedback_with_real_confidence_and_duration(client, analyst_headers, db_session):
    org_id = client.get("/auth/me", headers=analyst_headers).json()["organization_id"]
    client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    client.post("/correlate", headers=analyst_headers)
    incident_id = client.get("/incidents", headers=analyst_headers).json()["incidents"][0]["id"]
    run_response = _run_investigation(client, analyst_headers, incident_id)
    run_id = run_response.json()["run_id"]

    client.post(
        f"/incidents/{incident_id}/feedback",
        json={"rating": "accurate", "agent_run_id": run_id},
        headers=analyst_headers,
    )

    summary = get_evaluation_summary(db_session, org_id)
    accurate = summary["accuracy_correlation"]["accurate"]
    assert accurate["rated_investigations"] == 1
    assert accurate["avg_detection_confidence"] == 92  # FAKE_DETECTION's real confidence value
    assert accurate["avg_duration_seconds"] is not None
    # Not rated - must not be double-counted into an unrelated bucket.
    assert summary["accuracy_correlation"]["false_positive"]["rated_investigations"] == 0


def test_evaluation_summary_computes_human_override_rate(db_session, org_id):
    db_session.add_all([
        ProposedAction(organization_id=org_id, incident_id=1, description="a", status="approved"),
        ProposedAction(organization_id=org_id, incident_id=1, description="b", status="executed"),
        ProposedAction(organization_id=org_id, incident_id=1, description="c", status="rejected"),
        ProposedAction(organization_id=org_id, incident_id=1, description="d", status="pending"),  # not yet reviewed - excluded
    ])
    db_session.commit()

    summary = get_evaluation_summary(db_session, org_id)
    assert summary["proposed_actions_reviewed"] == 3  # pending excluded
    assert summary["proposed_actions_rejected"] == 1
    assert summary["human_override_rate_pct"] == round(100 / 3, 1)


def test_learning_evaluation_endpoint(client, viewer_headers):
    response = client.get("/learning/evaluation", headers=viewer_headers)
    assert response.status_code == 200
    body = response.json()
    assert "total_investigations" in body
    assert "accuracy_correlation" in body


def test_learning_evaluation_requires_authentication(client):
    assert client.get("/learning/evaluation").status_code == 401
