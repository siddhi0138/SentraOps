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


# --- model retirement fallback -------------------------------------------------

import httpx
import pytest
from groq import GroqError, NotFoundError

import app.ai as ai_module


def _not_found():
    request = httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions")
    return NotFoundError("model_not_found", response=httpx.Response(404, request=request), body=None)


@pytest.fixture(autouse=True)
def _reset_working_model():
    ai_module._working_model = None
    yield
    ai_module._working_model = None


def _ok_response(text='{"ok": true}'):
    response = MagicMock()
    response.choices = [MagicMock(message=MagicMock(content=text))]
    return response


def test_retired_model_falls_back_to_the_next_one_and_remembers_it(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "fake-key-for-test")
    monkeypatch.setenv("GROQ_MODEL", "llama-3.3-70b-versatile")  # what Render still has configured

    with patch("app.ai.Groq") as MockGroq:
        create = MockGroq.return_value.chat.completions.create
        create.side_effect = [_not_found(), _ok_response()]
        assert ai_module.chat_json("sys", "user") == {"ok": True}

        tried = [call.kwargs["model"] for call in create.call_args_list]
        assert tried == ["llama-3.3-70b-versatile", "openai/gpt-oss-120b"]
        assert ai_module._working_model == "openai/gpt-oss-120b"

        # The next call goes straight to the model that worked.
        create.reset_mock()
        create.side_effect = [_ok_response()]
        ai_module.chat_json("sys", "user")
        assert [call.kwargs["model"] for call in create.call_args_list] == ["openai/gpt-oss-120b"]


def test_gpt_oss_gets_low_reasoning_and_room_for_the_answer(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "fake-key-for-test")
    monkeypatch.delenv("GROQ_MODEL", raising=False)

    with patch("app.ai.Groq") as MockGroq:
        create = MockGroq.return_value.chat.completions.create
        create.return_value = _ok_response()
        ai_module.chat_json("sys", "user", max_tokens=400)

    kwargs = create.call_args.kwargs
    assert kwargs["model"] == "openai/gpt-oss-120b"
    assert kwargs["reasoning_effort"] == "low"
    assert kwargs["include_reasoning"] is False
    assert kwargs["max_tokens"] >= 2000
    assert kwargs["response_format"] == {"type": "json_object"}


def test_other_errors_are_not_retried_on_another_model(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "fake-key-for-test")

    with patch("app.ai.Groq") as MockGroq:
        create = MockGroq.return_value.chat.completions.create
        create.side_effect = GroqError("rate limited")
        with pytest.raises(ai_module.ChatProviderError):
            ai_module.chat_json("sys", "user")
    assert create.call_count == 1


def test_provider_error_when_every_model_is_missing(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "fake-key-for-test")

    with patch("app.ai.Groq") as MockGroq:
        MockGroq.return_value.chat.completions.create.side_effect = _not_found()
        with pytest.raises(ai_module.ChatProviderError):
            ai_module.chat_json("sys", "user")


# --- chat never returns an empty answer ------------------------------------------

def test_answer_question_retries_with_a_bigger_budget_when_the_first_answer_is_empty(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "fake-key-for-test")
    with patch("app.ai.Groq") as MockGroq:
        create = MockGroq.return_value.chat.completions.create
        create.side_effect = [_ok_response(None), _ok_response("The answer.")]
        assert ai_module.answer_question("what happened?", []) == "The answer."
    assert create.call_count == 2
    assert create.call_args_list[1].kwargs["max_tokens"] >= 3000


def test_answer_question_raises_a_readable_error_instead_of_returning_nothing(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "fake-key-for-test")
    with patch("app.ai.Groq") as MockGroq:
        MockGroq.return_value.chat.completions.create.return_value = _ok_response("   ")
        with pytest.raises(ai_module.ChatProviderError) as error:
            ai_module.answer_question("what happened?", [])
    assert "empty answer" in str(error.value)
