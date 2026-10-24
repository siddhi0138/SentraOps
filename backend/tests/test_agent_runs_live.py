from contextlib import ExitStack
from unittest.mock import patch

from tests.test_agents_coordinator import (
    FAKE_DETECTION,
    FAKE_INVESTIGATION,
    FAKE_REPORT,
    FAKE_RESPONSE,
    FAKE_RISK,
    FAKE_THREAT_INTEL,
)


def _create_incident(client, analyst_headers) -> int:
    client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    client.post("/correlate", headers=analyst_headers)
    return client.get("/incidents", headers=analyst_headers).json()["incidents"][0]["id"]


def _investigate_live(client, headers, incident_id, db_session, chat_json_kwargs=None):
    """Triggers the async endpoint. In tests, eager-mode Celery runs the
    task inline on its own db session (see conftest.py) - a genuinely
    different session than the one `client` reads through, exactly like a
    real separate worker process would be. `db_session.expire_all()`
    mirrors what a fresh request's session naturally gets in production
    (Depends(get_db) hands out a brand new session per request, so there's
    no stale identity-map read there); without it, `client`'s follow-up
    reads in this same test would return the pre-task-run cached objects."""
    kwargs = chat_json_kwargs or {}
    with ExitStack() as stack:
        stack.enter_context(patch("app.agents.detection.chat_json", **kwargs.get("detection", {"return_value": FAKE_DETECTION})))
        stack.enter_context(patch("app.agents.investigation.chat_json", return_value=FAKE_INVESTIGATION))
        stack.enter_context(patch("app.agents.threat_intel.chat_json", return_value=FAKE_THREAT_INTEL))
        stack.enter_context(patch("app.agents.risk.chat_json", return_value=FAKE_RISK))
        stack.enter_context(patch("app.agents.response.chat_json", return_value=FAKE_RESPONSE))
        stack.enter_context(patch("app.agents.report.chat_json", return_value=FAKE_REPORT))
        response = client.post(f"/incidents/{incident_id}/investigate-live", headers=headers)
    db_session.expire_all()
    return response


def test_investigate_live_returns_immediately_with_run_id(client, analyst_headers, db_session):
    incident_id = _create_incident(client, analyst_headers)
    response = _investigate_live(client, analyst_headers, incident_id, db_session)

    assert response.status_code == 200
    body = response.json()
    assert body["incident_id"] == incident_id
    assert body["status"] == "running"
    run_id = body["run_id"]

    # Eager-mode Celery already ran the task inline by the time we get here.
    detail = client.get(f"/agent-runs/{run_id}", headers=analyst_headers).json()
    assert detail["status"] == "completed"
    assert detail["result"]["detection"]["attack_pattern"] == "credential theft + lateral movement"
    assert len(detail["messages"]) == 6


def test_investigate_live_unknown_incident_returns_404(client, analyst_headers):
    response = client.post("/incidents/99999/investigate-live", headers=analyst_headers)
    assert response.status_code == 404


def test_investigate_live_requires_authentication(client):
    response = client.post("/incidents/1/investigate-live")
    assert response.status_code == 401


def test_viewer_cannot_investigate_live(client, analyst_headers, viewer_headers):
    incident_id = _create_incident(client, analyst_headers)
    response = client.post(f"/incidents/{incident_id}/investigate-live", headers=viewer_headers)
    assert response.status_code == 403


def test_investigate_live_persists_failed_run_on_config_error(client, analyst_headers, db_session):
    from app.ai import ChatConfigError

    incident_id = _create_incident(client, analyst_headers)
    response = _investigate_live(
        client,
        analyst_headers,
        incident_id,
        db_session,
        chat_json_kwargs={"detection": {"side_effect": ChatConfigError("GROQ_API_KEY is not set")}},
    )

    assert response.status_code == 200
    run_id = response.json()["run_id"]
    detail = client.get(f"/agent-runs/{run_id}", headers=analyst_headers).json()
    assert detail["status"] == "failed"
    assert detail["error"] == "GROQ_API_KEY is not set"


def test_list_all_agent_runs_across_incidents(client, analyst_headers, db_session):
    incident_1 = _create_incident(client, analyst_headers)
    _investigate_live(client, analyst_headers, incident_1, db_session)

    client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    client.post("/correlate", headers=analyst_headers)
    incidents = client.get("/incidents", headers=analyst_headers).json()["incidents"]
    incident_2 = next(i["id"] for i in incidents if i["id"] != incident_1)
    _investigate_live(client, analyst_headers, incident_2, db_session)

    response = client.get("/agent-runs", headers=analyst_headers)
    assert response.status_code == 200
    runs = response.json()["runs"]
    assert len(runs) == 2
    assert {r["incident_id"] for r in runs} == {incident_1, incident_2}
    assert all(r["incident_title"] for r in runs)


def test_list_all_agent_runs_filters_by_status(client, analyst_headers, db_session):
    incident_id = _create_incident(client, analyst_headers)
    _investigate_live(client, analyst_headers, incident_id, db_session)

    completed = client.get("/agent-runs", params={"status": "completed"}, headers=analyst_headers)
    assert completed.status_code == 200
    assert all(r["status"] == "completed" for r in completed.json()["runs"])

    failed = client.get("/agent-runs", params={"status": "failed"}, headers=analyst_headers)
    assert failed.json()["runs"] == []


def test_agent_runs_require_authentication(client):
    assert client.get("/agent-runs").status_code == 401


def test_agent_runs_ws_requires_token(client, analyst_headers, db_session):
    incident_id = _create_incident(client, analyst_headers)
    run_id = _investigate_live(client, analyst_headers, incident_id, db_session).json()["run_id"]

    with client.websocket_connect(f"/ws/agent-runs/{run_id}") as ws:
        data = ws.receive_json()
        assert data["type"] == "error"
        assert "token" in data["error"].lower()


def test_agent_runs_ws_rejects_invalid_token(client, analyst_headers, db_session):
    incident_id = _create_incident(client, analyst_headers)
    run_id = _investigate_live(client, analyst_headers, incident_id, db_session).json()["run_id"]

    with client.websocket_connect(f"/ws/agent-runs/{run_id}?token=garbage") as ws:
        data = ws.receive_json()
        assert data["type"] == "error"


def test_agent_runs_ws_unknown_run_id(client, analyst_headers):
    token = analyst_headers["Authorization"].split(" ")[1]
    with client.websocket_connect(f"/ws/agent-runs/99999?token={token}") as ws:
        data = ws.receive_json()
        assert data["type"] == "error"
        assert "not found" in data["error"].lower()


def test_agent_runs_ws_reports_already_completed_run(client, analyst_headers, db_session):
    incident_id = _create_incident(client, analyst_headers)
    run_id = _investigate_live(client, analyst_headers, incident_id, db_session).json()["run_id"]
    token = analyst_headers["Authorization"].split(" ")[1]

    # Eager-mode Celery already completed this run by the time
    # investigate-live returned, so there's no live pub/sub message left to
    # wait for (Redis doesn't replay history to new subscribers) - the
    # socket should report the already-terminal state immediately instead
    # of hanging.
    with client.websocket_connect(f"/ws/agent-runs/{run_id}?token={token}") as ws:
        data = ws.receive_json()
        assert data["type"] == "completed"
        assert data["run_id"] == run_id


def test_investigate_live_runs_in_background_thread_when_redis_is_down(client, analyst_headers, db_session):
    import time

    from app.main import celery_app

    incident_id = _create_incident(client, analyst_headers)
    was_eager = celery_app.conf.task_always_eager
    celery_app.conf.task_always_eager = False
    try:
        # The fake model replies must stay patched until the background thread is done,
        # unlike _investigate_live, which unpatches as soon as the request returns.
        with ExitStack() as stack:
            stack.enter_context(patch("app.main.redis_is_available", return_value=False))
            stack.enter_context(patch("app.agents.detection.chat_json", return_value=FAKE_DETECTION))
            stack.enter_context(patch("app.agents.investigation.chat_json", return_value=FAKE_INVESTIGATION))
            stack.enter_context(patch("app.agents.threat_intel.chat_json", return_value=FAKE_THREAT_INTEL))
            stack.enter_context(patch("app.agents.risk.chat_json", return_value=FAKE_RISK))
            stack.enter_context(patch("app.agents.response.chat_json", return_value=FAKE_RESPONSE))
            stack.enter_context(patch("app.agents.report.chat_json", return_value=FAKE_REPORT))

            response = client.post(f"/incidents/{incident_id}/investigate-live", headers=analyst_headers)
            assert response.status_code == 200
            assert response.json()["status"] == "running"  # returned immediately
            run_id = response.json()["run_id"]

            run = {}
            for _ in range(600):
                db_session.expire_all()
                run = client.get(f"/agent-runs/{run_id}", headers=analyst_headers).json()
                if run["status"] != "running":
                    break
                time.sleep(0.2)
    finally:
        celery_app.conf.task_always_eager = was_eager

    assert run["status"] == "completed"
    assert run["result"]["detection"]["attack_pattern"] == "credential theft + lateral movement"


def test_local_progress_events_are_recorded_and_replayable():
    from app.progress import local_events_since, publish_progress

    with patch("app.progress.get_client", side_effect=__import__("redis").ConnectionError("down")):
        publish_progress(987001, {"type": "started", "run_id": 987001})
        publish_progress(987001, {"type": "completed", "run_id": 987001})

    assert [e["type"] for e in local_events_since(987001, 0)] == ["started", "completed"]
    assert [e["type"] for e in local_events_since(987001, 1)] == ["completed"]
    assert local_events_since(987002, 0) == []


def test_agent_runs_ws_streams_in_process_progress_when_redis_is_down(client, analyst_headers, db_session):
    from app.db_models import AgentRun
    from app.progress import publish_progress

    incident_id = _create_incident(client, analyst_headers)
    # A run that is still going: created directly so nothing completes it behind our back.
    run = AgentRun(
        organization_id=client.get("/auth/me", headers=analyst_headers).json()["organization_id"],
        incident_id=incident_id,
        status="running",
    )
    db_session.add(run)
    db_session.commit()
    run_id = run.id

    token = analyst_headers["Authorization"].split(" ")[1]
    with patch("app.progress.get_client", side_effect=__import__("redis").ConnectionError("down")), \
         patch("app.main.redis_is_available", return_value=False):
        publish_progress(run_id, {"type": "started", "run_id": run_id})
        publish_progress(run_id, {"type": "agent_completed", "run_id": run_id, "agent": "detection"})
        publish_progress(run_id, {"type": "completed", "run_id": run_id})

        with client.websocket_connect(f"/ws/agent-runs/{run_id}?token={token}") as ws:
            received = [ws.receive_json()["type"] for _ in range(3)]

    assert received == ["started", "agent_completed", "completed"]
