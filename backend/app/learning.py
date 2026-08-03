from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.db_models import AgentRun, AnalystFeedback, Incident, ProposedAction

RATINGS = ("accurate", "false_positive", "missed_detection")
TREND_DAYS = 30


def record_feedback(
    db: Session,
    organization_id: int,
    incident_id: int,
    rating: str,
    note: str | None,
    reviewed_by_id: int,
    agent_run_id: int | None = None,
) -> AnalystFeedback:
    feedback = AnalystFeedback(
        organization_id=organization_id,
        incident_id=incident_id,
        agent_run_id=agent_run_id,
        rating=rating,
        note=note,
        reviewed_by_id=reviewed_by_id,
    )
    db.add(feedback)
    db.commit()
    db.refresh(feedback)
    return feedback


def list_feedback_for_incident(db: Session, incident_id: int) -> list[AnalystFeedback]:
    return (
        db.query(AnalystFeedback)
        .filter(AnalystFeedback.incident_id == incident_id)
        .order_by(AnalystFeedback.created_at.desc())
        .all()
    )


def get_feedback_stats(db: Session, organization_id: int) -> dict:
    """Aggregate accuracy over time - the platform's "model performance"
    view, computed from real analyst judgments rather than an offline eval
    set. Day-bucketing done in Python, not a dialect-specific SQL date
    function - the same standing reason as executive.py's incident trend
    (SQLite/Postgres datetime-comparison parity has bitten this project
    more than once already)."""
    all_feedback = db.query(AnalystFeedback).filter(AnalystFeedback.organization_id == organization_id).all()
    counts = {r: 0 for r in RATINGS}
    for f in all_feedback:
        counts[f.rating] = counts.get(f.rating, 0) + 1

    total = len(all_feedback)
    accuracy_rate = round(counts["accurate"] / total * 100, 1) if total else None

    since = (datetime.now(timezone.utc) - timedelta(days=TREND_DAYS)).replace(tzinfo=None)
    by_day: dict[str, dict[str, int]] = defaultdict(lambda: {r: 0 for r in RATINGS})
    for f in all_feedback:
        created = f.created_at
        created_naive = created.astimezone(timezone.utc).replace(tzinfo=None) if created.tzinfo else created
        if created_naive < since:
            continue
        day = created_naive.date().isoformat()
        by_day[day][f.rating] = by_day[day].get(f.rating, 0) + 1
    trend = [{"date": day, **day_counts} for day, day_counts in sorted(by_day.items())]

    return {
        "total_feedback": total,
        "counts": counts,
        "accuracy_rate": accuracy_rate,
        "trend": trend,
    }


def get_recent_corrections(db: Session, organization_id: int, limit: int = 5) -> list[dict]:
    """Past analyst corrections (false positives / missed detections with
    an explanatory note) - fed into future Detection Agent runs as real
    institutional feedback (see agents/memory.py's build_memory_context),
    the mechanism that actually closes this platform's learning loop."""
    rows = (
        db.query(AnalystFeedback)
        .join(Incident, AnalystFeedback.incident_id == Incident.id)
        .filter(
            AnalystFeedback.organization_id == organization_id,
            AnalystFeedback.rating.in_(["false_positive", "missed_detection"]),
            AnalystFeedback.note.isnot(None),
            AnalystFeedback.note != "",
        )
        .order_by(AnalystFeedback.created_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "incident_id": row.incident_id,
            "incident_title": row.incident.title if row.incident else "Unknown",
            "rating": row.rating,
            "note": row.note,
        }
        for row in rows
    ]


def get_evaluation_summary(db: Session, organization_id: int) -> dict:
    """Cross-references three real datasets this platform already persists
    for its own operational reasons (AgentRun timing/confidence,
    AnalystFeedback accuracy ratings, ProposedAction human review
    outcomes) into one evaluation view - deliberately NOT a synthetic
    benchmark or an invented "hallucination rate": every number here is
    something a human analyst or the AI itself already recorded for real.
    Genuinely NOT able to break accuracy down per-agent (Detection vs Risk
    vs ...) - an analyst rates one investigation as a whole via
    AnalystFeedback, never judges an individual agent's contribution
    separately, so pretending otherwise here would be fabricating
    precision the data doesn't support."""
    runs = (
        db.query(AgentRun)
        .filter(AgentRun.organization_id == organization_id, AgentRun.status == "completed", AgentRun.completed_at.isnot(None))
        .all()
    )
    durations = [(r.completed_at - r.started_at).total_seconds() for r in runs]
    avg_duration = round(sum(durations) / len(durations), 1) if durations else None

    feedback_by_run: dict[int, str] = {
        f.agent_run_id: f.rating
        for f in db.query(AnalystFeedback).filter(
            AnalystFeedback.organization_id == organization_id, AnalystFeedback.agent_run_id.isnot(None)
        )
    }

    # Real correlation, not a fabricated metric: does a run's own duration
    # or its Detection Agent's own stated confidence differ between
    # analyst-confirmed-accurate runs and ones later flagged
    # false_positive/missed_detection?
    duration_by_rating: dict[str, list[float]] = defaultdict(list)
    confidence_by_rating: dict[str, list[float]] = defaultdict(list)
    for run, duration in zip(runs, durations):
        rating = feedback_by_run.get(run.id)
        if not rating:
            continue
        duration_by_rating[rating].append(duration)
        detection_confidence = (run.result or {}).get("detection", {}).get("confidence")
        if isinstance(detection_confidence, (int, float)):
            confidence_by_rating[rating].append(detection_confidence)

    accuracy_correlation = {
        rating: {
            "rated_investigations": len(duration_by_rating.get(rating, [])),
            "avg_duration_seconds": round(sum(duration_by_rating[rating]) / len(duration_by_rating[rating]), 1)
            if duration_by_rating.get(rating)
            else None,
            "avg_detection_confidence": round(sum(confidence_by_rating[rating]) / len(confidence_by_rating[rating]), 1)
            if confidence_by_rating.get(rating)
            else None,
        }
        for rating in RATINGS
    }

    # "executed"/"execution_failed" both imply a prior human approval (see
    # ProposedAction's own docstring - nothing here ever auto-executes),
    # so both count as the human agreeing with the AI's proposal.
    reviewed = (
        db.query(ProposedAction)
        .filter(
            ProposedAction.organization_id == organization_id,
            ProposedAction.status.in_(["approved", "rejected", "executed", "execution_failed"]),
        )
        .all()
    )
    rejected = sum(1 for a in reviewed if a.status == "rejected")
    override_rate_pct = round(100 * rejected / len(reviewed), 1) if reviewed else None

    return {
        "total_investigations": len(runs),
        "avg_investigation_duration_seconds": avg_duration,
        "accuracy_correlation": accuracy_correlation,
        "human_override_rate_pct": override_rate_pct,
        "proposed_actions_reviewed": len(reviewed),
        "proposed_actions_rejected": rejected,
    }
