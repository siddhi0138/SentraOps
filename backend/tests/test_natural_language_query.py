from unittest.mock import patch

from app.ai import ChatConfigError, ChatProviderError

FAKE_FILTERS = {
    "event_type": "privilege_escalation",
    "severity": "high",
    "username": None,
    "host": None,
    "source_ip": None,
    "q": None,
}


def test_query_translates_and_filters_events(client, analyst_headers):
    client.post("/simulate/phishing_ransomware", headers=analyst_headers)

    with patch("app.main.translate_query", return_value=FAKE_FILTERS) as mock_translate:
        response = client.post(
            "/query",
            json={"question": "show me privilege escalation events"},
            headers=analyst_headers,
        )

    assert response.status_code == 200
    body = response.json()
    assert body["filters"] == FAKE_FILTERS
    assert all(e["event_type"] == "privilege_escalation" for e in body["events"])
    mock_translate.assert_called_once_with("show me privilege escalation events")


def test_query_rejects_empty_question(client, analyst_headers):
    response = client.post("/query", json={"question": "   "}, headers=analyst_headers)
    assert response.status_code == 422


def test_query_requires_authentication(client):
    response = client.post("/query", json={"question": "anything"})
    assert response.status_code == 401


def test_query_returns_503_when_not_configured(client, analyst_headers):
    with patch("app.main.translate_query", side_effect=ChatConfigError("GROQ_API_KEY is not set")):
        response = client.post("/query", json={"question": "anything"}, headers=analyst_headers)
    assert response.status_code == 503


def test_query_returns_502_on_provider_failure(client, analyst_headers):
    with patch("app.main.translate_query", side_effect=ChatProviderError("rate limited")):
        response = client.post("/query", json={"question": "anything"}, headers=analyst_headers)
    assert response.status_code == 502


def test_viewer_can_query(client, analyst_headers, viewer_headers):
    with patch("app.main.translate_query", return_value=FAKE_FILTERS):
        response = client.post("/query", json={"question": "anything"}, headers=viewer_headers)
    assert response.status_code == 200
