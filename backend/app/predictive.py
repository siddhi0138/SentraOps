from collections import defaultdict
from datetime import datetime, timedelta, timezone

import numpy as np
from sklearn.ensemble import IsolationForest
from sqlalchemy.orm import Session

from app.ai import chat_json
from app.db_models import Event, Incident

TREND_DAYS = 30
# IsolationForest needs several samples before "unusual" is a meaningful
# statement rather than noise - below this, report insufficient_data
# honestly instead of fitting a model on 2-3 points and calling it ML.
MIN_ENTITIES_FOR_ANOMALY_MODEL = 4
FEATURE_NAMES = ["event_count", "distinct_source_ips", "off_hours_ratio", "failed_login_ratio", "high_severity_ratio"]


def _entity_features(db: Session, organization_id: int) -> list[dict]:
    """One feature row per (host, username) actor seen in this org's real
    ingested events - the meaningful unit for "unusual authentication
    pattern" is a single actor's behavior across many events, not any one
    event in isolation."""
    events = db.query(Event).filter(Event.organization_id == organization_id, Event.username.isnot(None)).all()
    grouped: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for e in events:
        grouped[(e.host, e.username)].append(e)

    rows = []
    for (host, username), items in grouped.items():
        total = len(items)
        distinct_ips = len({e.source_ip for e in items if e.source_ip})
        off_hours = sum(1 for e in items if e.timestamp and (e.timestamp.hour < 6 or e.timestamp.hour >= 22))
        failed = sum(1 for e in items if e.event_type == "login_failed")
        high_sev = sum(1 for e in items if e.severity in ("high", "critical"))
        rows.append(
            {
                "host": host,
                "username": username,
                "event_count": total,
                "distinct_source_ips": distinct_ips,
                "off_hours_ratio": round(off_hours / total, 3),
                "failed_login_ratio": round(failed / total, 3),
                "high_severity_ratio": round(high_sev / total, 3),
            }
        )
    return rows


def detect_anomalous_entities(db: Session, organization_id: int) -> dict:
    """Fits an IsolationForest fresh on this org's real current data on every
    call (no persisted model file) - fine at this project's data volume,
    same "recompute over cached staleness" discipline as app/compliance.py's
    checks, and it means a control can never report a stale anomaly."""
    rows = _entity_features(db, organization_id)
    if len(rows) < MIN_ENTITIES_FOR_ANOMALY_MODEL:
        return {"status": "insufficient_data", "entities_analyzed": len(rows), "anomalies": []}

    X = np.array([[r[f] for f in FEATURE_NAMES] for r in rows])
    model = IsolationForest(n_estimators=200, contamination="auto", random_state=42)
    model.fit(X)
    scores = model.decision_function(X)  # higher = more normal
    predictions = model.predict(X)  # -1 = anomaly, 1 = normal

    anomalies = []
    for row, score, pred in zip(rows, scores, predictions):
        if pred != -1:
            continue
        reasons = []
        if row["distinct_source_ips"] >= 3:
            reasons.append(f"{row['distinct_source_ips']} distinct source IPs for one account")
        if row["off_hours_ratio"] > 0.5:
            reasons.append("majority of activity outside business hours")
        if row["failed_login_ratio"] > 0.3:
            reasons.append("high failed-login ratio")
        if row["high_severity_ratio"] > 0.3:
            reasons.append("high proportion of high/critical severity events")
        if not reasons:
            reasons.append("statistically unusual combination of activity features")
        anomalies.append({**row, "anomaly_score": round(float(-score), 4), "reasons": reasons})

    anomalies.sort(key=lambda a: a["anomaly_score"], reverse=True)
    return {"status": "ok", "entities_analyzed": len(rows), "anomalies": anomalies}


def privilege_escalation_trend(db: Session, organization_id: int) -> dict:
    """Real day-bucketed counts of this org's own privilege_escalation
    events over the trailing window, with a linear-fit slope for direction -
    not a fabricated forecast, a trend read off real history."""
    since = (datetime.now(timezone.utc) - timedelta(days=TREND_DAYS)).replace(tzinfo=None)
    events = (
        db.query(Event)
        .filter(Event.organization_id == organization_id, Event.event_type == "privilege_escalation")
        .all()
    )
    by_day: dict[str, int] = defaultdict(int)
    for e in events:
        ts = e.timestamp
        ts_naive = ts.astimezone(timezone.utc).replace(tzinfo=None) if ts.tzinfo else ts
        if ts_naive < since:
            continue
        by_day[ts_naive.date().isoformat()] += 1

    if not by_day:
        return {"direction": "none", "slope_per_day": 0.0, "daily_counts": [], "total": 0}

    days_sorted = sorted(by_day.items())
    counts = [c for _, c in days_sorted]
    if len(counts) < 2:
        direction, slope = "insufficient_data", 0.0
    else:
        slope = float(np.polyfit(np.arange(len(counts)), counts, 1)[0])
        direction = "rising" if slope > 0.05 else "falling" if slope < -0.05 else "stable"

    return {
        "direction": direction,
        "slope_per_day": round(slope, 3),
        "daily_counts": [{"date": d, "count": c} for d, c in days_sorted],
        "total": sum(counts),
    }


def risk_drift(db: Session, organization_id: int, window: int = 5) -> dict:
    """Compares the average risk_score of this org's most recent incidents
    against the ones before that - real historical incident data, split in
    half (or into `window`-sized halves once there are enough), not a
    forecast of incidents that haven't happened."""
    incidents = (
        db.query(Incident).filter(Incident.organization_id == organization_id).order_by(Incident.created_at.asc()).all()
    )
    scores = [i.risk_score for i in incidents]
    if len(scores) < 2:
        return {"direction": "insufficient_data", "recent_average": None, "prior_average": None, "drift": None}

    split = min(window, len(scores) // 2) or 1
    recent, prior = scores[-split:], scores[:-split]
    recent_avg, prior_avg = sum(recent) / len(recent), sum(prior) / len(prior)
    drift = recent_avg - prior_avg
    direction = "worsening" if drift > 5 else "improving" if drift < -5 else "stable"

    return {
        "direction": direction,
        "recent_average": round(recent_avg, 1),
        "prior_average": round(prior_avg, 1),
        "drift": round(drift, 1),
    }


def get_predictive_summary(db: Session, organization_id: int) -> dict:
    return {
        "anomalous_entities": detect_anomalous_entities(db, organization_id),
        "privilege_escalation_trend": privilege_escalation_trend(db, organization_id),
        "risk_drift": risk_drift(db, organization_id),
    }


_BRIEFING_SYSTEM_PROMPT = """You are CyberSentinel AI, producing a predictive threat-likelihood briefing \
for a security analyst. You are given real statistical signals computed from \
this organization's own historical data: anomalous user/host behavior \
detected by an anomaly-detection model, a privilege-escalation event trend, \
and a risk-score drift comparison. This is NOT a report of attacks that \
already happened - it is a forward-looking read of "what is more likely \
given these real signals." Be calibrated and honest: if the signals are \
weak or insufficient, say so rather than inventing urgency.

Respond with ONLY a valid JSON object (no markdown fences, no extra text). \
CRITICAL: every value must be a properly double-quoted JSON string (or an \
array of double-quoted strings) - never write a value without surrounding \
quotes, no matter how long.

Exact keys required:
- "headline": a JSON string, one sentence on overall predictive risk level.
- "summary": a JSON string, 2-4 sentences interpreting the real signals given.
- "likely_scenarios": a JSON array of up to 3 short JSON strings, each a \
specific forward-looking statement grounded in the data given (e.g. a named \
anomalous account, a rising trend) - not generic security advice.
- "recommended_watch": a JSON string, one to two sentences on what to monitor next.

Base everything strictly on the signals given. Do not invent entities, \
numbers, or scenarios not present in the data. If signals are insufficient, \
say the confidence is low rather than fabricating a scenario.

Example of the exact shape required (values illustrative only, not real data):
{"headline": "Predictive risk is currently low with one account worth watching.", \
"summary": "One account shows anomalous authentication behavior across multiple \
IPs. No meaningful privilege-escalation trend or risk drift was detected.", \
"likely_scenarios": ["Account j.mehta on FINANCE-PC-21 shows unusual multi-IP login activity"], \
"recommended_watch": "Monitor the flagged account for further off-hours activity."}"""


def _format_summary_for_prompt(summary: dict) -> str:
    lines = []
    anomalies = summary["anomalous_entities"]
    if anomalies["status"] == "insufficient_data":
        lines.append(f"Anomaly detection: insufficient data ({anomalies['entities_analyzed']} actor(s) analyzed, need at least {MIN_ENTITIES_FOR_ANOMALY_MODEL}).")
    elif not anomalies["anomalies"]:
        lines.append(f"Anomaly detection: {anomalies['entities_analyzed']} actor(s) analyzed, no anomalies flagged.")
    else:
        lines.append(f"Anomaly detection: {anomalies['entities_analyzed']} actor(s) analyzed, {len(anomalies['anomalies'])} flagged as anomalous:")
        for a in anomalies["anomalies"][:5]:
            lines.append(f"  - {a['username']}@{a['host']}: score {a['anomaly_score']}, reasons: {', '.join(a['reasons'])}")

    trend = summary["privilege_escalation_trend"]
    lines.append(f"Privilege escalation trend (last {TREND_DAYS}d): {trend['direction']}, {trend['total']} total event(s), slope {trend['slope_per_day']}/day.")

    drift = summary["risk_drift"]
    if drift["direction"] == "insufficient_data":
        lines.append("Risk drift: insufficient incident history.")
    else:
        lines.append(f"Risk drift: {drift['direction']} (recent avg risk {drift['recent_average']} vs prior avg {drift['prior_average']}, drift {drift['drift']}).")

    return "\n".join(lines)


def generate_predictive_briefing(summary: dict) -> dict:
    return chat_json(_BRIEFING_SYSTEM_PROMPT, _format_summary_for_prompt(summary), max_tokens=500, feature="predictive_briefing")
