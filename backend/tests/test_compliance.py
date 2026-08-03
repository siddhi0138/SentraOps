import json
from pathlib import Path
from unittest.mock import patch

from app.ai import ChatConfigError, ChatProviderError
from app.compliance import evaluate_controls
from app.correlation import run_correlation
from app.db_models import IncidentComment, ProposedAction, User
from app.ingestion import ingest
from tests.test_proposed_actions import _create_incident_with_proposed_actions

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"


def _by_key(controls: list[dict], key: str) -> dict:
    return next(c for c in controls if c["check_key"] == key)


def _ransomware_incident(db_session, org_id):
    ingest(db_session, org_id, "windows", json.loads((SAMPLES / "windows_events.json").read_text()))
    ingest(db_session, org_id, "firewall", json.loads((SAMPLES / "firewall.json").read_text()))
    ingest(db_session, org_id, "syslog", (SAMPLES / "syslog.log").read_text().splitlines())
    return run_correlation(db_session, org_id)[0]


def test_evaluate_controls_returns_full_seeded_catalog(db_session, org_id):
    controls = evaluate_controls(db_session, org_id)
    assert len(controls) == 21
    frameworks = {c["framework"] for c in controls}
    assert frameworks == {"SOC2", "ISO27001", "GDPR", "NIST_CSF", "MITRE_ATTACK", "CIS", "PCI_DSS"}
    assert all(c["status"] in ("satisfied", "partial", "not_satisfied") for c in controls)


def test_rbac_role_separation_partial_with_single_role(db_session, org_id):
    from app.auth import hash_password

    db_session.add(User(organization_id=org_id, email="only-admin@example.com", hashed_password=hash_password("x"), role="admin"))
    db_session.commit()

    result = _by_key(evaluate_controls(db_session, org_id), "rbac_role_separation")
    assert result["status"] == "partial"


def test_rbac_role_separation_satisfied_with_multiple_roles(db_session, org_id):
    from app.auth import hash_password

    db_session.add(User(organization_id=org_id, email="admin2@example.com", hashed_password=hash_password("x"), role="admin"))
    db_session.add(User(organization_id=org_id, email="analyst2@example.com", hashed_password=hash_password("x"), role="analyst"))
    db_session.commit()

    result = _by_key(evaluate_controls(db_session, org_id), "rbac_role_separation")
    assert result["status"] == "satisfied"


def test_password_hashing_satisfied_for_real_bcrypt_hash(db_session, org_id):
    from app.auth import hash_password

    db_session.add(User(organization_id=org_id, email="u@example.com", hashed_password=hash_password("x"), role="admin"))
    db_session.commit()

    result = _by_key(evaluate_controls(db_session, org_id), "password_hashing")
    assert result["status"] == "satisfied"


def test_availability_monitoring_is_always_satisfied(db_session, org_id):
    result = _by_key(evaluate_controls(db_session, org_id), "availability_monitoring")
    assert result["status"] == "satisfied"


def test_incident_response_exercised_not_satisfied_with_no_completed_runs(db_session, org_id):
    result = _by_key(evaluate_controls(db_session, org_id), "incident_response_exercised")
    assert result["status"] == "not_satisfied"


def test_incident_response_plans_documented_satisfied_after_correlation(db_session, org_id):
    _ransomware_incident(db_session, org_id)
    result = _by_key(evaluate_controls(db_session, org_id), "incident_response_plans_documented")
    assert result["status"] == "satisfied"


def test_incident_response_plans_documented_not_satisfied_with_no_incidents(db_session, org_id):
    result = _by_key(evaluate_controls(db_session, org_id), "incident_response_plans_documented")
    assert result["status"] == "not_satisfied"


def test_breach_notification_immediate_satisfied_after_correlation(db_session, org_id):
    from app.auth import hash_password

    # _notify_responders only has someone to notify if the org actually has
    # an admin/analyst user - a real org always does (the org creator), but
    # the bare org_id fixture doesn't, so seed one first.
    db_session.add(User(organization_id=org_id, email="responder@example.com", hashed_password=hash_password("x"), role="admin"))
    db_session.commit()

    _ransomware_incident(db_session, org_id)
    result = _by_key(evaluate_controls(db_session, org_id), "breach_notification_immediate")
    assert result["status"] == "satisfied"


def test_breach_notification_immediate_partial_with_no_responders_to_notify(db_session, org_id):
    # Honest edge case: an org with incidents but nobody to notify (no
    # admin/analyst users) correctly reports partial, not a false pass.
    _ransomware_incident(db_session, org_id)
    result = _by_key(evaluate_controls(db_session, org_id), "breach_notification_immediate")
    assert result["status"] == "partial"


def test_audit_trail_not_satisfied_then_satisfied_after_comment(db_session, org_id):
    from app.auth import hash_password

    incident = _ransomware_incident(db_session, org_id)
    assert _by_key(evaluate_controls(db_session, org_id), "audit_trail_exists")["status"] == "not_satisfied"

    user = User(organization_id=org_id, email="commenter@example.com", hashed_password=hash_password("x"), role="analyst")
    db_session.add(user)
    db_session.commit()
    db_session.add(IncidentComment(incident_id=incident.id, author_id=user.id, body="Investigating."))
    db_session.commit()

    assert _by_key(evaluate_controls(db_session, org_id), "audit_trail_exists")["status"] == "satisfied"


def test_response_action_approval_gate_satisfied_with_no_executed_actions(db_session, org_id):
    result = _by_key(evaluate_controls(db_session, org_id), "response_action_approval_gate")
    assert result["status"] == "satisfied"


def test_response_action_approval_gate_satisfied_when_reviewed(client, analyst_headers, admin_headers):
    _, action_ids = _create_incident_with_proposed_actions(client, analyst_headers)
    client.patch(f"/proposed-actions/{action_ids[0]}", json={"status": "approved"}, headers=analyst_headers)
    client.post(
        "/response-action-instances",
        json={"plugin_key": "webhook", "name": "SOC Slack", "config": {"webhook_url": "https://example.com/hook"}},
        headers=admin_headers,
    )
    with patch("app.plugins.actions.webhook.WebhookAction.execute", return_value=(True, "ok")):
        client.post(f"/proposed-actions/{action_ids[0]}/execute", headers=analyst_headers)

    response = client.get("/compliance/controls", headers=analyst_headers)
    result = next(c for c in response.json()["controls"] if c["check_key"] == "response_action_approval_gate")
    assert result["status"] == "satisfied"


def test_response_action_approval_gate_not_satisfied_if_reviewer_missing(db_session, org_id):
    from app.db_models import Incident

    incident = Incident(organization_id=org_id, title="t", report="r")
    db_session.add(incident)
    db_session.flush()
    # Directly fabricate a bypass scenario the real API can never produce
    # (execute always requires a prior approval, which always sets
    # reviewed_by_id) - proving the check would actually catch it if the
    # gate were ever bypassed.
    db_session.add(
        ProposedAction(
            organization_id=org_id,
            incident_id=incident.id,
            category="containment",
            description="x",
            status="executed",
            reviewed_by_id=None,
        )
    )
    db_session.commit()

    result = _by_key(evaluate_controls(db_session, org_id), "response_action_approval_gate")
    assert result["status"] == "not_satisfied"


def test_compliance_controls_endpoint(client, viewer_headers):
    response = client.get("/compliance/controls", headers=viewer_headers)
    assert response.status_code == 200
    assert len(response.json()["controls"]) == 21


def test_compliance_controls_requires_authentication(client):
    assert client.get("/compliance/controls").status_code == 401


def test_compliance_report_requires_analyst_or_admin(client, viewer_headers, analyst_headers):
    fake_report = {"overall_posture": "x", "summary": "y", "gaps": [], "next_steps": "z"}
    assert client.post("/compliance/report", headers=viewer_headers).status_code == 403
    with patch("app.main.generate_compliance_report", return_value=fake_report):
        response = client.post("/compliance/report", headers=analyst_headers)
    assert response.status_code == 200
    assert response.json()["report"] == fake_report
    assert len(response.json()["controls"]) == 21


def test_compliance_report_not_configured(client, analyst_headers):
    with patch("app.main.generate_compliance_report", side_effect=ChatConfigError("GROQ_API_KEY is not set")):
        response = client.post("/compliance/report", headers=analyst_headers)
    assert response.status_code == 503


def test_compliance_report_provider_error(client, analyst_headers):
    with patch("app.main.generate_compliance_report", side_effect=ChatProviderError("rate limited")):
        response = client.post("/compliance/report", headers=analyst_headers)
    assert response.status_code == 502


def _privilege_escalation_incident(db_session, org_id):
    # No critical severity, no data_transfer event type - keeps
    # correlation._classify() on the privilege-escalation branch rather
    # than the ransomware/exfiltration branch, which checks first.
    ingest(db_session, org_id, "generic", [
        {"timestamp": "2026-07-24T09:00:00", "host": "HOST-A", "username": "alice", "source_ip": "9.9.9.9",
         "event_type": "privilege_escalation", "severity": "high", "message": "new admin account created"},
        {"timestamp": "2026-07-24T09:01:00", "host": "HOST-A", "username": "alice", "source_ip": "9.9.9.9",
         "event_type": "privilege_escalation", "severity": "high", "message": "added to admins group"},
    ])
    return run_correlation(db_session, org_id)[0]


def test_nist_detection_capability_not_satisfied_before_any_correlation(db_session, org_id):
    result = _by_key(evaluate_controls(db_session, org_id), "nist_detection_capability_exercised")
    assert result["status"] == "not_satisfied"


def test_nist_detection_capability_satisfied_after_correlation(db_session, org_id):
    _privilege_escalation_incident(db_session, org_id)
    result = _by_key(evaluate_controls(db_session, org_id), "nist_detection_capability_exercised")
    assert result["status"] == "satisfied"


def test_nist_recovery_planning_partial_while_incident_open(db_session, org_id):
    _privilege_escalation_incident(db_session, org_id)
    result = _by_key(evaluate_controls(db_session, org_id), "nist_recovery_planning")
    assert result["status"] == "partial"


def test_nist_recovery_planning_satisfied_once_incident_closed(db_session, org_id):
    from datetime import datetime, timezone
    from app.db_models import Incident

    incident = _privilege_escalation_incident(db_session, org_id)
    db_incident = db_session.get(Incident, incident.id)
    db_incident.status = "closed"
    db_incident.closed_at = datetime.now(timezone.utc)
    db_session.commit()

    result = _by_key(evaluate_controls(db_session, org_id), "nist_recovery_planning")
    assert result["status"] == "satisfied"


def test_mitre_privilege_escalation_detected(db_session, org_id):
    _privilege_escalation_incident(db_session, org_id)
    result = _by_key(evaluate_controls(db_session, org_id), "mitre_privilege_escalation_detected")
    assert result["status"] == "satisfied"


def test_mitre_privilege_escalation_not_satisfied_for_unrelated_incident(db_session, org_id):
    _ransomware_incident(db_session, org_id)
    result = _by_key(evaluate_controls(db_session, org_id), "mitre_privilege_escalation_detected")
    assert result["status"] == "not_satisfied"


def test_mitre_exfiltration_detected(db_session, org_id):
    _ransomware_incident(db_session, org_id)
    result = _by_key(evaluate_controls(db_session, org_id), "mitre_exfiltration_detected")
    assert result["status"] == "satisfied"


def test_mitre_threat_intel_matched_via_seeded_demo_indicator(db_session, org_id):
    # The ransomware sample data uses 185.220.101.45, which is the
    # migration-seeded demo Tor-exit-node indicator - a real match, not a
    # test-only stub.
    _ransomware_incident(db_session, org_id)
    result = _by_key(evaluate_controls(db_session, org_id), "mitre_threat_intel_matched")
    assert result["status"] == "satisfied"


def test_mitre_threat_intel_not_matched_without_known_indicator(db_session, org_id):
    _privilege_escalation_incident(db_session, org_id)
    result = _by_key(evaluate_controls(db_session, org_id), "mitre_threat_intel_matched")
    assert result["status"] == "not_satisfied"


def test_cis_network_monitoring_not_satisfied_without_firewall_events(db_session, org_id):
    _privilege_escalation_incident(db_session, org_id)
    result = _by_key(evaluate_controls(db_session, org_id), "cis_network_monitoring")
    assert result["status"] == "not_satisfied"


def test_cis_network_monitoring_satisfied_with_firewall_events(db_session, org_id):
    ingest(db_session, org_id, "firewall", json.loads((SAMPLES / "firewall.json").read_text()))
    result = _by_key(evaluate_controls(db_session, org_id), "cis_network_monitoring")
    assert result["status"] == "satisfied"


def test_pci_vulnerability_management_partial_with_only_demo_seed(db_session, org_id):
    result = _by_key(evaluate_controls(db_session, org_id), "pci_vulnerability_management")
    assert result["status"] == "partial"


def test_pci_vulnerability_management_satisfied_after_real_sync(db_session, org_id):
    from app.threat_intel_hub import upsert_indicator

    upsert_indicator(
        db_session,
        indicator="evil.example.com",
        indicator_type="domain",
        verdict="malicious",
        confidence=90,
        source="URLhaus",
    )
    result = _by_key(evaluate_controls(db_session, org_id), "pci_vulnerability_management")
    assert result["status"] == "satisfied"


def test_reused_checks_are_aliased_under_new_keys_per_framework(db_session, org_id):
    # Same underlying evaluator, different check_key per framework row -
    # proves the alias wiring in CHECKS actually reaches every seeded row,
    # not just the original SOC2 one.
    from app.auth import hash_password

    db_session.add(User(organization_id=org_id, email="alias-test@example.com", hashed_password=hash_password("x"), role="admin"))
    db_session.commit()

    controls = evaluate_controls(db_session, org_id)
    for key in ["password_hashing", "cis_password_hashing", "pci_password_hashing"]:
        assert _by_key(controls, key)["status"] == "satisfied"
