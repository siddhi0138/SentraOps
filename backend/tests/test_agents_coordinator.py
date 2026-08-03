from contextlib import ExitStack
from unittest.mock import patch

FAKE_DETECTION = {
    "assessment": "Clear credential theft followed by lateral movement.",
    "attack_pattern": "credential theft + lateral movement",
    "confidence": 92,
    "key_indicators": ["svc_update privilege escalation", "known-bad source IP"],
}

FAKE_INVESTIGATION = {
    "timeline_narrative": "The attacker phished credentials, then escalated privileges and exfiltrated data.",
    "key_findings": ["PowerShell executed on FINANCE-PC-21", "mysqldump run as root on db-server-03"],
    "attacker_objective": "data exfiltration",
}

FAKE_THREAT_INTEL = {
    "summary": "Source IP matches a known Tor exit node associated with ransomware infrastructure.",
    "mitre_techniques": [{"id": "T1078", "name": "Valid Accounts", "evidence": "svc_update privilege escalation"}],
    "malware_association": None,
    "confidence": 85,
}

FAKE_RISK = {
    "business_risk_score": 96,
    "business_risk_level": "critical",
    "explanation": "The finance database server holds customer data and was directly accessed.",
    "most_critical_asset": "db-server-03",
}

FAKE_RESPONSE = {
    "actions": [
        {"category": "containment", "description": "Disable account svc_update and rotate its credentials."},
        {"category": "eradication", "description": "Remove persistence mechanisms on db-server-03."},
    ],
    "urgency": "immediate",
}

FAKE_REPORT = {
    "executive_summary": "Attackers accessed the finance database using a compromised service account.",
    "technical_summary": "svc_update was used for privilege escalation and mysqldump on db-server-03.",
    "compliance_notes": "Customer records in the finance database may trigger breach-notification requirements.",
    "customer_notification": "Notify affected customers within regulatory timelines.",
}


def _create_one_incident(client, analyst_headers) -> int:
    client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    client.post("/correlate", headers=analyst_headers)
    return client.get("/incidents", headers=analyst_headers).json()["incidents"][0]["id"]


def _patched_investigate(client, headers, incident_id):
    with ExitStack() as stack:
        stack.enter_context(patch("app.agents.detection.chat_json", return_value=FAKE_DETECTION))
        stack.enter_context(patch("app.agents.investigation.chat_json", return_value=FAKE_INVESTIGATION))
        stack.enter_context(patch("app.agents.threat_intel.chat_json", return_value=FAKE_THREAT_INTEL))
        stack.enter_context(patch("app.agents.risk.chat_json", return_value=FAKE_RISK))
        stack.enter_context(patch("app.agents.response.chat_json", return_value=FAKE_RESPONSE))
        stack.enter_context(patch("app.agents.report.chat_json", return_value=FAKE_REPORT))
        return client.post(f"/incidents/{incident_id}/investigate", headers=headers)


def test_investigate_runs_full_agent_chain_in_order(client, analyst_headers):
    incident_id = _create_one_incident(client, analyst_headers)

    response = _patched_investigate(client, analyst_headers, incident_id)

    assert response.status_code == 200
    state = response.json()
    assert state["incident_id"] == incident_id
    assert state["stage"] == "done"

    for key in ("detection", "investigation", "threat_intel_findings", "risk", "response", "report"):
        assert state[key], f"expected {key} to be populated"

    assert state["detection"]["attack_pattern"] == "credential theft + lateral movement"
    assert state["investigation"]["attacker_objective"] == "data exfiltration"
    assert state["threat_intel_findings"]["mitre_techniques"][0]["id"] == "T1078"
    assert state["risk"]["business_risk_score"] == 96
    assert state["risk"]["most_critical_asset"] == "db-server-03"

    # the Response Agent's proposals must come back as persisted rows
    # (real ids, pending status) - not just the raw LLM output - since a
    # human approves/rejects them in a later request.
    proposed = state["response"]["proposed_actions"]
    assert len(proposed) == 2
    assert all(a["status"] == "pending" for a in proposed)
    assert all(a["id"] for a in proposed)
    assert proposed[0]["category"] == "containment"

    assert state["report"]["compliance_notes"]
    assert state["report"]["customer_notification"] == "Notify affected customers within regulatory timelines."

    agent_order = [m["agent"] for m in state["messages"]]
    assert agent_order == ["detection", "investigation", "threat_intel", "risk", "response", "report"]


def test_investigate_unknown_incident_returns_404(client, analyst_headers):
    response = client.post("/incidents/99999/investigate", headers=analyst_headers)
    assert response.status_code == 404


def test_investigate_requires_authentication(client):
    response = client.post("/incidents/1/investigate")
    assert response.status_code == 401


def test_viewer_cannot_investigate(client, analyst_headers, viewer_headers):
    incident_id = _create_one_incident(client, analyst_headers)
    response = _patched_investigate(client, viewer_headers, incident_id)
    assert response.status_code == 403


def test_investigate_returns_503_when_not_configured(client, analyst_headers):
    from app.ai import ChatConfigError

    incident_id = _create_one_incident(client, analyst_headers)
    with patch("app.agents.detection.chat_json", side_effect=ChatConfigError("GROQ_API_KEY is not set")):
        response = client.post(f"/incidents/{incident_id}/investigate", headers=analyst_headers)
    assert response.status_code == 503


def test_investigate_returns_502_on_provider_failure(client, analyst_headers):
    from app.ai import ChatProviderError

    incident_id = _create_one_incident(client, analyst_headers)
    with patch("app.agents.detection.chat_json", side_effect=ChatProviderError("rate limited")):
        response = client.post(f"/incidents/{incident_id}/investigate", headers=analyst_headers)
    assert response.status_code == 502
