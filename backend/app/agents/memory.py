from sqlalchemy.orm import Session

from app.db_models import AgentRun, Incident
from app.learning import get_recent_corrections
from app.rag import search as rag_search


def _repeat_entities(db: Session, incident: Incident, field: str, values: list[str]) -> list[dict]:
    """Finds other incidents that share a host/user with this one - the
    platform's simplest form of "does this actor/asset have a history".
    Scoped to the incident's own organization - this is "institutional
    memory" the AI reasons from, so leaking another tenant's incident
    history in here isn't just a data bug, it's the agents' own reasoning
    citing a different company's confidential security data."""
    if not values:
        return []
    lowered = {v.lower() for v in values}

    others = (
        db.query(Incident)
        .filter(Incident.organization_id == incident.organization_id, Incident.id != incident.id)
        .order_by(Incident.created_at.desc())
        .all()
    )
    matches = []
    for other in others:
        other_values = {v.lower() for v in (getattr(other, field) or [])}
        overlap = other_values & lowered
        if overlap:
            matches.append(
                {
                    "incident_id": other.id,
                    "title": other.title,
                    "risk_level": other.risk_level,
                    "status": other.status,
                    "created_at": other.created_at.isoformat() if other.created_at else None,
                    "shared": sorted(overlap),
                }
            )
    return matches[:5]


def build_memory_context(db: Session, incident: Incident) -> dict:
    """Cross-incident institutional memory: what this platform has already
    learned about the hosts/users involved, and which past investigations
    read most like this one. Built entirely from data already persisted
    (Embedding table from Milestone 2's RAG, Incident.affected_hosts/users,
    completed AgentRuns) rather than a separate long-term-memory store -
    this platform's Postgres+pgvector already is that store."""
    query_text = f"{incident.title}\n{incident.report}".strip()
    similar_raw = (
        rag_search(db, incident.organization_id, query_text, content_type="incident", k=6) if query_text else []
    )

    similar_incidents = []
    for row in similar_raw:
        if row["content_id"] == incident.id or not row["content_id"]:
            continue
        past = db.get(Incident, row["content_id"])
        if not past:
            continue
        completed_run = (
            db.query(AgentRun)
            .filter(AgentRun.incident_id == past.id, AgentRun.status == "completed")
            .order_by(AgentRun.started_at.desc())
            .first()
        )
        prior_summary = None
        if completed_run and completed_run.result:
            prior_summary = (completed_run.result.get("report") or {}).get("executive_summary")

        similar_incidents.append(
            {
                "incident_id": past.id,
                "title": past.title,
                "risk_level": past.risk_level,
                "status": past.status,
                "similarity": row["score"],
                "prior_report_summary": prior_summary,
            }
        )
        if len(similar_incidents) >= 3:
            break

    return {
        "similar_past_incidents": similar_incidents,
        "repeat_hosts": _repeat_entities(db, incident, "affected_hosts", incident.affected_hosts),
        "repeat_users": _repeat_entities(db, incident, "affected_users", incident.affected_users),
        # The Learning Loop's actual feedback mechanism: real analyst
        # corrections on past investigations, not model retraining (out
        # of scope) - see app/learning.py.
        "recent_corrections": get_recent_corrections(db, incident.organization_id),
    }
