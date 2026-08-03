from unittest.mock import patch

from app.ai import ChatConfigError, ChatProviderError

FAKE_EXPLANATION = {
    "explanation": "A new admin-level account was created on this host, which is unusual outside of provisioning windows.",
    "is_suspicious": True,
    "recommended_action": "Check other events from this host in the last hour.",
}


def _create_one_event(client, analyst_headers) -> int:
    client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    return client.get("/events", headers=analyst_headers).json()["events"][0]["id"]


def test_explain_event_returns_structured_explanation(client, analyst_headers):
    event_id = _create_one_event(client, analyst_headers)

    with patch("app.main.explain_event", return_value=FAKE_EXPLANATION) as mock_explain:
        response = client.get(f"/events/{event_id}/explain", headers=analyst_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["is_suspicious"] is True
    assert "admin-level account" in body["explanation"]

    # the event's own fields must be what gets passed in, not a placeholder
    call_args = mock_explain.call_args
    event_text = call_args.args[0]
    assert "host:" in event_text
    assert "message:" in event_text


def test_explain_unknown_event_returns_404(client, analyst_headers):
    response = client.get("/events/99999/explain", headers=analyst_headers)
    assert response.status_code == 404


def test_explain_event_requires_authentication(client):
    response = client.get("/events/1/explain")
    assert response.status_code == 401


def test_explain_event_returns_503_when_not_configured(client, analyst_headers):
    event_id = _create_one_event(client, analyst_headers)
    with patch("app.main.explain_event", side_effect=ChatConfigError("GROQ_API_KEY is not set")):
        response = client.get(f"/events/{event_id}/explain", headers=analyst_headers)
    assert response.status_code == 503


def test_explain_event_returns_502_on_provider_failure(client, analyst_headers):
    event_id = _create_one_event(client, analyst_headers)
    with patch("app.main.explain_event", side_effect=ChatProviderError("rate limited")):
        response = client.get(f"/events/{event_id}/explain", headers=analyst_headers)
    assert response.status_code == 502


def test_viewer_can_explain_event(client, analyst_headers, viewer_headers):
    event_id = _create_one_event(client, analyst_headers)
    with patch("app.main.explain_event", return_value=FAKE_EXPLANATION):
        response = client.get(f"/events/{event_id}/explain", headers=viewer_headers)
    assert response.status_code == 200
