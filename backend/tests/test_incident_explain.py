from unittest.mock import patch

from app.ai import ChatConfigError, ChatProviderError

FAKE_EXPLANATION = {
    "explanation": "Critical because an admin account was created and used to exfiltrate data.",
    "timeline_narrative": "The attacker phished credentials, escalated privileges, then exfiltrated data.",
    "attack_type": "Ransomware / Data Exfiltration",
    "affected_user": "svc_update",
    "affected_assets": "FINANCE-PC-21, db-server-03",
    "impact": "Potential customer data exposure.",
}


def _create_one_incident(client, analyst_headers) -> int:
    client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    client.post("/correlate", headers=analyst_headers)
    return client.get("/incidents", headers=analyst_headers).json()["incidents"][0]["id"]


def test_explain_incident_returns_structured_explanation(client, analyst_headers):
    incident_id = _create_one_incident(client, analyst_headers)

    with patch("app.main.explain_incident", return_value={**FAKE_EXPLANATION, "confidence": 96}) as mock_explain:
        response = client.get(f"/incidents/{incident_id}/explain", headers=analyst_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["attack_type"] == "Ransomware / Data Exfiltration"
    assert body["confidence"] == 96
    assert "svc_update" in body["affected_user"]

    # the incident's own report + confidence must be what gets passed in,
    # not something empty/placeholder
    call_args = mock_explain.call_args
    assert "Incident Report" in call_args.args[0]
    assert call_args.args[1] == 96


def test_explain_unknown_incident_returns_404(client, analyst_headers):
    response = client.get("/incidents/99999/explain", headers=analyst_headers)
    assert response.status_code == 404


def test_explain_requires_authentication(client):
    response = client.get("/incidents/1/explain")
    assert response.status_code == 401


def test_explain_returns_503_when_not_configured(client, analyst_headers):
    incident_id = _create_one_incident(client, analyst_headers)
    with patch("app.main.explain_incident", side_effect=ChatConfigError("GROQ_API_KEY is not set")):
        response = client.get(f"/incidents/{incident_id}/explain", headers=analyst_headers)
    assert response.status_code == 503


def test_explain_returns_502_on_provider_failure(client, analyst_headers):
    incident_id = _create_one_incident(client, analyst_headers)
    with patch("app.main.explain_incident", side_effect=ChatProviderError("rate limited")):
        response = client.get(f"/incidents/{incident_id}/explain", headers=analyst_headers)
    assert response.status_code == 502


def test_viewer_can_explain_incident(client, analyst_headers, viewer_headers):
    incident_id = _create_one_incident(client, analyst_headers)
    with patch("app.main.explain_incident", return_value={**FAKE_EXPLANATION, "confidence": 96}):
        response = client.get(f"/incidents/{incident_id}/explain", headers=viewer_headers)
    assert response.status_code == 200
