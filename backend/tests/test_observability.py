from unittest.mock import MagicMock, patch

from app.ai import ChatProviderError, chat_json
from app.metrics import ai_call_duration_seconds, ai_calls_total, ai_cost_usd_total, ai_tokens_total
from app.observability import get_ai_observability_summary
from groq import GroqError


def _counter_value(counter, **labels) -> float:
    for metric in counter.collect():
        for s in metric.samples:
            if s.name.endswith("_total") and s.labels == labels:
                return s.value
    return 0.0


def _histogram_count(histogram, **labels) -> float:
    for metric in histogram.collect():
        for s in metric.samples:
            if s.name.endswith("_count") and s.labels == labels:
                return s.value
    return 0.0


def test_call_groq_records_success_calls_tokens_and_cost(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "fake-key-for-test")

    fake_response = MagicMock()
    fake_response.choices = [MagicMock(message=MagicMock(content='{"ok": true}'))]
    fake_response.usage = MagicMock(prompt_tokens=100, completion_tokens=50)

    before_calls = _counter_value(ai_calls_total, feature="test_metrics_feature", status="success")
    before_prompt_tokens = _counter_value(ai_tokens_total, feature="test_metrics_feature", token_type="prompt")
    before_cost = _counter_value(ai_cost_usd_total, feature="test_metrics_feature")
    before_duration_count = _histogram_count(ai_call_duration_seconds, feature="test_metrics_feature")

    with patch("app.ai.Groq") as MockGroq:
        MockGroq.return_value.chat.completions.create.return_value = fake_response
        chat_json("system", "user", feature="test_metrics_feature")

    assert _counter_value(ai_calls_total, feature="test_metrics_feature", status="success") == before_calls + 1
    assert _counter_value(ai_tokens_total, feature="test_metrics_feature", token_type="prompt") == before_prompt_tokens + 100
    # cost = 100 * 0.59/1e6 + 50 * 0.79/1e6
    expected_cost_delta = 100 * (0.59 / 1_000_000) + 50 * (0.79 / 1_000_000)
    assert abs(_counter_value(ai_cost_usd_total, feature="test_metrics_feature") - before_cost - expected_cost_delta) < 1e-9
    assert _histogram_count(ai_call_duration_seconds, feature="test_metrics_feature") == before_duration_count + 1


def test_call_groq_records_error_status_and_does_not_record_tokens(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "fake-key-for-test")

    before_errors = _counter_value(ai_calls_total, feature="test_metrics_error_feature", status="error")
    before_prompt_tokens = _counter_value(ai_tokens_total, feature="test_metrics_error_feature", token_type="prompt")

    with patch("app.ai.Groq") as MockGroq:
        MockGroq.return_value.chat.completions.create.side_effect = GroqError("boom")
        try:
            chat_json("system", "user", feature="test_metrics_error_feature")
            assert False, "expected ChatProviderError"
        except ChatProviderError:
            pass

    assert _counter_value(ai_calls_total, feature="test_metrics_error_feature", status="error") == before_errors + 1
    assert _counter_value(ai_tokens_total, feature="test_metrics_error_feature", token_type="prompt") == before_prompt_tokens


def test_call_groq_skips_token_metrics_when_usage_missing_real_ints(monkeypatch):
    # Plenty of existing tests mock the Groq response as a bare MagicMock()
    # without setting .usage, which would auto-vivify .usage.prompt_tokens
    # as another MagicMock, not a real int - this must not crash or record
    # garbage into a Counter.
    monkeypatch.setenv("GROQ_API_KEY", "fake-key-for-test")

    fake_response = MagicMock()
    fake_response.choices = [MagicMock(message=MagicMock(content='{"ok": true}'))]
    # fake_response.usage left as an auto-vivified MagicMock, not set explicitly.

    before_prompt_tokens = _counter_value(ai_tokens_total, feature="test_metrics_no_usage_feature", token_type="prompt")

    with patch("app.ai.Groq") as MockGroq:
        MockGroq.return_value.chat.completions.create.return_value = fake_response
        chat_json("system", "user", feature="test_metrics_no_usage_feature")

    assert _counter_value(ai_tokens_total, feature="test_metrics_no_usage_feature", token_type="prompt") == before_prompt_tokens


def test_get_ai_observability_summary_reflects_recorded_calls(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "fake-key-for-test")

    fake_response = MagicMock()
    fake_response.choices = [MagicMock(message=MagicMock(content='{"ok": true}'))]
    fake_response.usage = MagicMock(prompt_tokens=10, completion_tokens=5)

    with patch("app.ai.Groq") as MockGroq:
        MockGroq.return_value.chat.completions.create.return_value = fake_response
        chat_json("system", "user", feature="test_summary_feature")

    summary = get_ai_observability_summary()
    row = next(r for r in summary["features"] if r["feature"] == "test_summary_feature")
    assert row["calls_success"] >= 1
    assert row["prompt_tokens"] >= 10
    assert row["completion_tokens"] >= 5
    assert row["avg_duration_seconds"] is not None
    assert row["success_rate_pct"] == 100.0
    assert row["estimated_cost_usd"] > 0


def test_observability_endpoint(client, viewer_headers):
    response = client.get("/observability/ai-summary", headers=viewer_headers)
    assert response.status_code == 200
    body = response.json()
    assert "features" in body
    assert "totals" in body


def test_observability_endpoint_requires_authentication(client):
    assert client.get("/observability/ai-summary").status_code == 401
