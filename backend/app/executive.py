from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.ai import chat_json
from app.db_models import AgentRun, Incident, ProposedAction, ThreatIndicator

TREND_DAYS = 14


def get_summary(db: Session, organization_id: int) -> dict:
    """Real SQL-backed aggregates for the executive view - counts via
    COUNT/GROUP BY (same standing "don't sample a capped list client-side"
    discipline as GET /stats), day-bucketing and time-to-close averaging
    done in Python rather than a dialect-specific SQL date function (this
    project has hit enough SQLite-vs-Postgres surprises - see db_models.py's
    EmbeddingVector and the asset-upsert tzinfo bug - that a portable
    Python loop over a bounded recent window is the safer default here)."""
    open_incidents_q = db.query(Incident).filter(Incident.organization_id == organization_id, Incident.status == "open")
    open_critical = open_incidents_q.filter(Incident.risk_level == "critical").count()
    open_high = open_incidents_q.filter(Incident.risk_level == "high").count()

    pending_actions = (
        db.query(ProposedAction)
        .join(Incident, ProposedAction.incident_id == Incident.id)
        .filter(Incident.organization_id == organization_id, ProposedAction.status == "pending")
        .count()
    )

    running_investigations = (
        db.query(AgentRun).filter(AgentRun.organization_id == organization_id, AgentRun.status == "running").count()
    )

    # Global, not org-scoped - see ThreatIndicator's own docstring for why.
    threat_indicators_tracked = db.query(ThreatIndicator).count()

    # Filtering "last N days" in SQL would mean comparing Incident.created_at
    # (naive on SQLite after a round-trip, aware on Postgres - the same
    # standing gotcha ingestion.py's asset-upsert code hit once already)
    # against a Python datetime of the *other* kind, which is a silent
    # mis-comparison on at least one dialect, not just a crash. Simpler and
    # dialect-safe: fetch this org's incidents (fine at this project's
    # demo/portfolio data volume, same reasoning used elsewhere in this
    # codebase) and do the recency filtering/bucketing in Python, where
    # normalizing to naive UTC before comparing is one explicit line.
    since = (datetime.now(timezone.utc) - timedelta(days=TREND_DAYS)).replace(tzinfo=None)
    by_day: dict[str, dict[str, int]] = defaultdict(lambda: {"low": 0, "medium": 0, "high": 0, "critical": 0})
    for incident in db.query(Incident).filter(Incident.organization_id == organization_id).all():
        created = incident.created_at
        created_naive = created.astimezone(timezone.utc).replace(tzinfo=None) if created.tzinfo else created
        if created_naive < since:
            continue
        day = created_naive.date().isoformat()
        by_day[day][incident.risk_level] = by_day[day].get(incident.risk_level, 0) + 1
    incident_trend = [{"date": day, **counts} for day, counts in sorted(by_day.items())]

    closed_incidents = (
        db.query(Incident)
        .filter(Incident.organization_id == organization_id, Incident.status == "closed", Incident.closed_at.isnot(None))
        .all()
    )
    if closed_incidents:
        total_hours = sum((i.closed_at - i.created_at).total_seconds() / 3600 for i in closed_incidents)
        mean_time_to_close_hours = round(total_hours / len(closed_incidents), 1)
    else:
        mean_time_to_close_hours = None

    top_incidents = (
        db.query(Incident)
        .filter(Incident.organization_id == organization_id, Incident.status == "open")
        .order_by(Incident.risk_score.desc())
        .limit(5)
        .all()
    )

    return {
        "open_critical_incidents": open_critical,
        "open_high_incidents": open_high,
        "pending_actions": pending_actions,
        "running_investigations": running_investigations,
        "threat_indicators_tracked": threat_indicators_tracked,
        "mean_time_to_close_hours": mean_time_to_close_hours,
        "incident_trend": incident_trend,
        "top_incidents": [i.to_summary_dict() for i in top_incidents],
    }


_BRIEFING_SYSTEM_PROMPT = """You are SentraOps, producing a security briefing for a company's \
executive leadership (CEO/CFO/board level, not technical staff). You are given \
real aggregate statistics from the security platform - not raw logs. Write in \
plain business language: no jargon, no event IDs, no protocol names. Focus on \
business risk, trend direction, and where leadership attention should go.

Respond with ONLY a valid JSON object (no markdown fences, no extra text). \
CRITICAL: every value must be a properly double-quoted JSON string (or an \
array of double-quoted strings) - never write a value without surrounding \
quotes, no matter how long.

Exact keys required:
- "headline": a JSON string, one sentence summarizing the current security posture.
- "summary": a JSON string, 2-4 sentences of narrative context, referencing \
the real numbers given (e.g. how many critical incidents are open, whether \
the trend is worsening or improving).
- "key_risks": a JSON array of up to 3 short JSON strings, each naming a \
specific concrete risk grounded in the data given (a named top incident, a \
rising trend, a large pending-action backlog) - not generic security advice.
- "recommended_focus": a JSON string, one to two sentences on what \
leadership should prioritize or ask about next.

Base everything strictly on the statistics given. Do not invent incidents, \
numbers, or risks not present in the data.

Example of the exact shape required (values illustrative only, not real data):
{"headline": "Security posture is stable with one open incident under review.", \
"summary": "There is one open high-risk incident affecting a single host. No \
other critical activity was recorded in the last two weeks.", "key_risks": \
["One open high-risk incident on HOST-1"], "recommended_focus": "Confirm \
containment status of the open incident."}"""


def _format_summary_for_prompt(summary: dict) -> str:
    lines = [
        f"Open critical incidents: {summary['open_critical_incidents']}",
        f"Open high-risk incidents: {summary['open_high_incidents']}",
        f"Proposed actions awaiting human approval: {summary['pending_actions']}",
        f"AI investigations currently running: {summary['running_investigations']}",
        f"Threat intel indicators tracked platform-wide: {summary['threat_indicators_tracked']}",
    ]
    if summary["mean_time_to_close_hours"] is not None:
        lines.append(f"Average time to close a resolved incident: {summary['mean_time_to_close_hours']} hours")
    if summary["incident_trend"]:
        lines.append("Incidents per day over the last two weeks: " + ", ".join(f"{d['date']}={sum(v for k, v in d.items() if k != 'date')}" for d in summary["incident_trend"]))
    if summary["top_incidents"]:
        lines.append("Top open incidents by risk score:")
        for inc in summary["top_incidents"]:
            lines.append(f"- \"{inc['title']}\" (risk {inc['risk_score']}/100, {inc['risk_level']}, affecting {', '.join(inc['affected_hosts']) or 'unknown hosts'})")
    return "\n".join(lines)


def generate_briefing(summary: dict) -> dict:
    return chat_json(_BRIEFING_SYSTEM_PROMPT, _format_summary_for_prompt(summary), max_tokens=500, feature="executive_briefing")
