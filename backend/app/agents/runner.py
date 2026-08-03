from datetime import datetime, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.agents.graph_context import build_graph_context
from app.agents.memory import build_memory_context
from app.db_models import AgentMessage, AgentRun, Asset, Incident, ProposedAction
from app.metrics import agent_investigation_duration_seconds, agent_investigations_total


def _duration_seconds(start: datetime | None, end: datetime | None) -> float | None:
    """SQLite drops tzinfo on datetime round-trips (Postgres doesn't) - a
    reloaded `run.started_at` can come back naive while `end` (just
    constructed in Python) is aware, and subtracting the two raises
    TypeError. Already bit this project once (see the asset-upsert
    datetime bug); normalize instead of assuming both sides match."""
    if start is None or end is None:
        return None
    if start.tzinfo is None and end.tzinfo is not None:
        end = end.replace(tzinfo=None)
    elif end.tzinfo is None and start.tzinfo is not None:
        start = start.replace(tzinfo=None)
    return (end - start).total_seconds()


def gather_investigation_inputs(db: Session, incident: Incident) -> tuple[list[dict], list[dict], dict, dict]:
    """The inputs every investigation (sync or async) needs to assemble
    before invoking the agent graph - shared so the two entry points can't
    silently drift on what context the agents get."""
    timeline = [e.to_dict() for e in incident.events]
    hosts_lower = [h.lower() for h in incident.affected_hosts]
    assets = (
        db.query(Asset)
        .filter(Asset.organization_id == incident.organization_id, func.lower(Asset.host).in_(hosts_lower))
        .all()
        if hosts_lower
        else []
    )
    memory = build_memory_context(db, incident)
    graph_context = build_graph_context(incident)
    return timeline, [a.to_dict() for a in assets], memory, graph_context


def persist_investigation_result(db: Session, run: AgentRun, incident_id: int, final_state: dict) -> list[ProposedAction]:
    """The Response Agent only ever proposes - persist each proposal as its
    own row so the human-approval decision survives past this request/task,
    plus the full inter-agent message log."""
    persisted_actions = []
    for action in final_state.get("response", {}).get("proposed_actions", []):
        proposed = ProposedAction(
            organization_id=run.organization_id,
            incident_id=incident_id,
            agent_run_id=run.id,
            category=action.get("category", "containment"),
            description=action.get("description", ""),
        )
        db.add(proposed)
        persisted_actions.append(proposed)

    for message in final_state.get("messages", []):
        db.add(AgentMessage(run_id=run.id, agent=message["agent"], content=message["content"]))

    run.status = "completed"
    run.completed_at = datetime.now(timezone.utc)
    run.result = {k: v for k, v in final_state.items() if k != "messages"}
    db.commit()
    for proposed in persisted_actions:
        db.refresh(proposed)

    agent_investigations_total.labels(status="completed").inc()
    duration = _duration_seconds(run.started_at, run.completed_at)
    if duration is not None:
        agent_investigation_duration_seconds.observe(duration)

    return persisted_actions


def mark_run_failed(db: Session, run: AgentRun, error: str) -> None:
    run.status = "failed"
    run.error = error
    run.completed_at = datetime.now(timezone.utc)
    db.commit()
    agent_investigations_total.labels(status="failed").inc()
