from unittest.mock import patch

from app.ai import ChatConfigError, ChatProviderError


def test_chat_returns_grounded_answer(client, analyst_headers):
    client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    client.post("/correlate", headers=analyst_headers)

    with patch("app.main.answer_question", return_value="This looks like a ransomware attack on FINANCE-PC-21.") as mock_answer:
        response = client.post("/chat", json={"question": "Why is this incident critical?"}, headers=analyst_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["question"] == "Why is this incident critical?"
    assert "ransomware" in body["answer"]
    assert len(body["sources"]) > 0

    # the endpoint must actually pass retrieved evidence to the LLM call,
    # not an empty list - otherwise "RAG" is just a chat wrapper
    call_args = mock_answer.call_args
    assert call_args.args[0] == "Why is this incident critical?"
    assert len(call_args.args[1]) > 0


def test_chat_requires_authentication(client):
    response = client.post("/chat", json={"question": "anything"})
    assert response.status_code == 401


def test_viewer_can_chat(client, viewer_headers):
    with patch("app.main.answer_question", return_value="answer"):
        response = client.post("/chat", json={"question": "anything"}, headers=viewer_headers)
    assert response.status_code == 200


def test_chat_rejects_empty_question(client, analyst_headers):
    response = client.post("/chat", json={"question": "   "}, headers=analyst_headers)
    assert response.status_code == 422


def test_chat_returns_503_when_not_configured(client, analyst_headers):
    with patch("app.main.answer_question", side_effect=ChatConfigError("GROQ_API_KEY is not set")):
        response = client.post("/chat", json={"question": "anything"}, headers=analyst_headers)
    assert response.status_code == 503


def test_chat_returns_502_on_provider_failure(client, analyst_headers):
    with patch("app.main.answer_question", side_effect=ChatProviderError("rate limited")):
        response = client.post("/chat", json={"question": "anything"}, headers=analyst_headers)
    assert response.status_code == 502
