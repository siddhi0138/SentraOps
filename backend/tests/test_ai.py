import json
import os
from unittest.mock import MagicMock, patch

from app.ai import ChatConfigError, explain_incident, translate_query


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


def test_translate_query_drops_hallucinated_event_type_and_severity(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "fake-key-for-test")

    # A model that ignores the allowed-values instruction and invents its own
    # labels must not leak them into a "==" filter - it would just silently
    # zero out results instead of matching anything.
    fake_content = json.dumps(
        {
            "event_type": "made_up_type",
            "severity": "extreme",
            "username": "alice",
            "host": None,
            "source_ip": None,
            "q": None,
        }
    )
    fake_response = MagicMock()
    fake_response.choices = [MagicMock(message=MagicMock(content=fake_content))]

    with patch("app.ai.Groq") as MockGroq:
        MockGroq.return_value.chat.completions.create.return_value = fake_response
        result = translate_query("show me alice's extreme made-up stuff")

    assert result["event_type"] is None
    assert result["severity"] is None
    assert result["username"] == "alice"


def test_translate_query_falls_back_to_empty_filters_on_invalid_json(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "fake-key-for-test")

    fake_response = MagicMock()
    fake_response.choices = [MagicMock(message=MagicMock(content="not valid json"))]

    with patch("app.ai.Groq") as MockGroq:
        MockGroq.return_value.chat.completions.create.return_value = fake_response
        result = translate_query("anything")

    assert result == {
        "event_type": None,
        "severity": None,
        "username": None,
        "host": None,
        "source_ip": None,
        "q": None,
    }
