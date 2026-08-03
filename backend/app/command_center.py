from sqlalchemy.orm import Session

from app.db_models import Incident, ProposedAction


def get_queue(db: Session, organization_id: int) -> dict:
    """The SOC Command Center's operational "what needs attention right
    now" view - a single aggregate query over things this platform already
    tracks (open incidents, pending human-approval actions), not a new
    concept of its own. Deliberately doesn't duplicate GET /agent-runs -
    the frontend calls that directly for the running-investigations
    section, since that endpoint already does exactly this job."""
    open_incidents = (
        db.query(Incident)
        .filter(Incident.organization_id == organization_id, Incident.status == "open")
        .order_by(Incident.risk_score.desc(), Incident.created_at.asc())
        .limit(20)
        .all()
    )
    unassigned = sum(1 for i in open_incidents if i.assignee_id is None)

    pending_actions = (
        db.query(ProposedAction)
        .join(Incident, ProposedAction.incident_id == Incident.id)
        .filter(Incident.organization_id == organization_id, ProposedAction.status == "pending")
        .order_by(ProposedAction.created_at.asc())
        .limit(50)
        .all()
    )

    return {
        "open_incidents": [i.to_summary_dict() for i in open_incidents],
        "unassigned_open_incidents": unassigned,
        "pending_actions": [
            {**a.to_dict(), "incident_title": a.incident.title if a.incident else None} for a in pending_actions
        ],
    }
