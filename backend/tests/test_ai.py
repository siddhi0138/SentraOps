import os
from unittest.mock import MagicMock, patch

from app.ai import ChatConfigError, explain_incident


def test_explain_incident_raises_config_error_without_api_key(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    try:
        explain_incident("some report", 90)
        assert False, "expected ChatConfigError"
    except ChatConfigError:
        pass


def test_explain_incident_falls_back_gracefully_on_invalid_json(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "fake-key-for-test")

    fake_response = MagicMock()
    fake_response.choices = [MagicMock(message=MagicMock(content="not valid json, just prose"))]

    with patch("app.ai.Groq") as MockGroq:
        MockGroq.return_value.chat.completions.create.return_value = fake_response
        result = explain_incident("some report", 90)

    assert result["explanation"] == "not valid json, just prose"
    assert result["confidence"] == 90
    assert result["attack_type"] == "Unknown"
