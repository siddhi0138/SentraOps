from app.agents.coordinator import stream_investigation
from app.agents.runner import gather_investigation_inputs, mark_run_failed, persist_investigation_result
from app.ai import ChatConfigError, ChatProviderError
from app.celery_app import celery_app
from app.db_models import AgentRun, Incident
from app.progress import publish_progress
from app.streaming import consume_available


def _default_session_factory():
    from app.db import SessionLocal

    return SessionLocal()


# Swappable so tests can point the task at the same in-memory test database
# the rest of a test uses, instead of the real module-level SessionLocal -
# which in tests is bound to an unrelated throwaway db (see conftest.py's
# DATABASE_URL/db_session split; the same reason `get_db` is a FastAPI
# dependency override rather than a hardcoded import). Celery workers are
# separate processes in production, so this has to be swappable module
# state rather than an argument passed through `.delay()`.
_session_factory = _default_session_factory


def set_session_factory(factory) -> None:
    global _session_factory
    _session_factory = factory


def reset_session_factory() -> None:
    global _session_factory
    _session_factory = _default_session_factory


def run_investigation_job(db, run_id: int, incident_id: int) -> None:
    """The actual work, independent of Celery - lets tests call this
    directly with a known db session instead of going through `.delay()`
    when they just want to check persistence behavior."""
    # Local import: app.slack_bot imports app.tasks (investigate_incident_task,
    # for the Slack "/sentraops investigate" command and Investigate button),
    # so importing it back at this module's top level would be a circular
    # import - deferring to call time sidesteps it, same pattern
    # app/correlation.py and app/agents/runner.py already use for the same
    # reason.
    from app.slack_bot import notify_agent_progress, notify_run_failed

    run = db.get(AgentRun, run_id)
    incident = db.get(Incident, incident_id)
    if run is None or incident is None:
        return

    timeline, assets, memory, graph_context = gather_investigation_inputs(db, incident)
    publish_progress(run_id, {"type": "started", "run_id": run_id})

    final_state = None
    try:
        for agent_name, state in stream_investigation(incident, timeline, assets, memory, graph_context):
            final_state = state
            last_message = state["messages"][-1]["content"] if state.get("messages") else None
            publish_progress(
                run_id,
                {"type": "agent_completed", "run_id": run_id, "agent": agent_name, "message": last_message},
            )
            try:
                notify_agent_progress(db, run, incident, agent_name, last_message)
            except Exception:
                pass
    except ChatConfigError:
        mark_run_failed(db, run, "GROQ_API_KEY is not set")
        publish_progress(run_id, {"type": "failed", "run_id": run_id, "error": run.error})
        try:
            notify_run_failed(db, run, incident, run.error)
        except Exception:
            pass
        return
    except ChatProviderError as exc:
        mark_run_failed(db, run, str(exc))
        publish_progress(run_id, {"type": "failed", "run_id": run_id, "error": run.error})
        try:
            notify_run_failed(db, run, incident, run.error)
        except Exception:
            pass
        return

    persist_investigation_result(db, run, incident_id, final_state)
    publish_progress(run_id, {"type": "completed", "run_id": run_id})


@celery_app.task(name="investigate_incident_task")
def investigate_incident_task(run_id: int, incident_id: int) -> None:
    db = _session_factory()
    try:
        run_investigation_job(db, run_id, incident_id)
    finally:
        db.close()


@celery_app.task(name="consume_ingest_stream_task")
def consume_ingest_stream_task(organization_id: int) -> None:
    """Dispatched right after POST /ingest/{source_type}/stream publishes -
    runs on a separate worker process in production, same as
    investigate_incident_task above (and picks up the same
    test-swapped session factory in eager-mode tests, see conftest.py)."""
    db = _session_factory()
    try:
        consume_available(db, organization_id)
    finally:
        db.close()


@celery_app.task(name="daily_slack_summaries_task")
def daily_slack_summaries_task() -> None:
    """Celery Beat hook (app/celery_app.py's beat_schedule) - fires once a
    day, no request/user behind it, so it goes straight to app/slack_bot.py
    rather than through any endpoint."""
    from app.slack_bot import send_daily_summaries

    db = _session_factory()
    try:
        send_daily_summaries(db)
    finally:
        db.close()
