from unittest.mock import MagicMock, patch

import pytest

import app.ai as ai_module
from app.agents import response as response_agent
from app.agents import threat_intel as threat_intel_agent
from app.agents.normalize import action_list, technique_list
from app.agents.state import AgentState


def _reply(content):
    response = MagicMock()
    response.choices = [MagicMock(message=MagicMock(content=content))]
    return response


@pytest.fixture(autouse=True)
def _groq_key(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "fake-key-for-test")
    ai_module._working_model = None
    yield
    ai_module._working_model = None


# --- chat_json tolerates replies that aren't a JSON object -----------------------

@pytest.mark.parametrize("content", [None, "", "   ", "[1, 2, 3]", '"just a string"', "42", "null"])
def test_chat_json_never_raises_on_odd_replies(content):
    with patch("app.ai.Groq") as MockGroq:
        MockGroq.return_value.chat.completions.create.return_value = _reply(content)
        result = ai_module.chat_json("system", "user")
    assert isinstance(result, dict)
    assert "_raw" in result


def test_chat_json_still_returns_a_normal_object():
    with patch("app.ai.Groq") as MockGroq:
        MockGroq.return_value.chat.completions.create.return_value = _reply('{"a": 1}')
        assert ai_module.chat_json("system", "user") == {"a": 1}


# --- normalizers ---------------------------------------------------------------

def test_technique_list_accepts_strings_objects_and_junk():
    assert technique_list(["T1059", {"id": "T1021", "name": "SMB"}, "", None, 5]) == [{"id": "T1059"}, {"id": "T1021", "name": "SMB"}]
    assert technique_list("T1059") == [{"id": "T1059"}]
    assert technique_list(None) == []
    assert technique_list({"id": "T1"}) == [{"id": "T1"}]


def test_action_list_accepts_strings_objects_and_junk():
    actions = action_list(["Isolate host FIN-01", {"category": "eradication", "description": "Reset password"}, {"description": None}, 7])
    assert actions[0] == {"category": "containment", "description": "Isolate host FIN-01"}
    assert actions[1]["category"] == "eradication" and actions[1]["description"] == "Reset password"
    assert actions[2] == {"category": "containment", "description": ""}
    assert len(actions) == 3
    assert action_list(None) == []


# --- the agents that parsed model output strictly ---------------------------------

def _state() -> AgentState:
    return {
        "incident": {"title": "Test incident", "risk_score": 80, "risk_level": "high", "confidence": 70},
        "timeline": [],
        "known_threat_intel": [],
        "messages": [],
    }


def test_threat_intel_agent_survives_string_techniques():
    with patch("app.agents.threat_intel.chat_json", return_value={"summary": "s", "mitre_techniques": ["T1059", "T1021"]}):
        update = threat_intel_agent.run(_state())
    assert [t["id"] for t in update["threat_intel_findings"]["mitre_techniques"]] == ["T1059", "T1021"]
    assert "T1059, T1021" in update["messages"][-1]["content"]


def test_response_agent_survives_string_actions():
    state = _state()
    with patch("app.agents.response.chat_json", return_value={"actions": ["Isolate host", "Reset credentials"], "urgency": "high"}):
        update = response_agent.run(state)
    proposed = update["response"]["proposed_actions"]
    assert [a["description"] for a in proposed] == ["Isolate host", "Reset credentials"]
    assert all(a["category"] == "containment" for a in proposed)


# --- endpoint safety nets ---------------------------------------------------------

def _incident(client, headers):
    client.post("/simulate/phishing_ransomware", headers=headers)
    client.post("/correlate", headers=headers)
    return client.get("/incidents", headers=headers).json()["incidents"][0]["id"]


def test_unexpected_investigation_error_is_a_readable_failed_run_not_a_crash(client, analyst_headers):
    incident_id = _incident(client, analyst_headers)
    with patch("app.main.run_investigation", side_effect=KeyError("risk_score")):
        response = client.post(f"/incidents/{incident_id}/investigate", headers=analyst_headers)

    assert response.status_code == 500
    assert "Investigation failed: KeyError" in response.json()["detail"]

    runs = client.get(f"/incidents/{incident_id}/agent-runs", headers=analyst_headers).json()["runs"]
    assert runs[0]["status"] == "failed"
    detail = client.get(f"/agent-runs/{runs[0]['id']}", headers=analyst_headers).json()
    assert "KeyError" in detail["error"]


def test_any_unhandled_error_still_carries_cors_headers(client, analyst_headers):
    # Starlette's own 500 page has no CORS headers, so the browser used to report a CORS
    # error that hid the real problem.
    headers = {**analyst_headers, "Origin": "https://example-frontend.onrender.com"}
    with patch("app.main.get_scenario", side_effect=RuntimeError("boom")):
        response = client.post("/simulate/phishing_ransomware", headers=headers)

    assert response.status_code == 500
    assert response.json() == {"detail": "Internal error: RuntimeError"}
    assert response.headers.get("access-control-allow-origin") in ("*", "https://example-frontend.onrender.com")
