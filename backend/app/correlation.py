import uuid

from sqlalchemy.orm import Session

from app.db_models import Event, Incident, Notification, User
from app.rag import store_embedding
from app.threat_intel_hub import lookup_many_with_live_fallback

ALERT_SEVERITIES = {"medium", "high", "critical"}
SEVERITY_WEIGHTS = {"low": 5, "medium": 15, "high": 25, "critical": 35}


class _DisjointSet:
    def __init__(self, items):
        self.parent = {item: item for item in items}

    def find(self, x):
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b):
        root_a, root_b = self.find(a), self.find(b)
        if root_a != root_b:
            self.parent[root_a] = root_b


def _norm(value: str | None) -> str | None:
    # Hostnames and usernames are case-insensitive in practice (DNS, AD),
    # and the same host/user routinely shows up with different casing across
    # Windows/Linux/firewall log sources for the same physical asset.
    return value.lower() if value else value


def _dedupe_case_insensitive(values) -> list[str]:
    seen: dict[str, str] = {}
    for value in values:
        seen.setdefault(value.lower(), value)
    return sorted(seen.values())


def _cluster_alerts(alerts: list[Event]) -> list[list[Event]]:
    """Groups alerts into connected components: two alerts are linked if they
    share a username, host, or source IP. This lets several unrelated attacks
    ingested in the same batch become separate incidents instead of one blob."""
    dsu = _DisjointSet(a.id for a in alerts)
    key_to_ids: dict[tuple[str, str], list[int]] = {}

    for alert in alerts:
        for key in (("username", _norm(alert.username)), ("host", _norm(alert.host)), ("source_ip", alert.source_ip)):
            if key[1]:
                key_to_ids.setdefault(key, []).append(alert.id)

    for ids in key_to_ids.values():
        for other_id in ids[1:]:
            dsu.union(ids[0], other_id)

    groups: dict[int, list[Event]] = {}
    for alert in alerts:
        groups.setdefault(dsu.find(alert.id), []).append(alert)

    return list(groups.values())


def _identity(cluster: list[Event]) -> dict[str, set[str]]:
    return {
        "usernames": {_norm(e.username) for e in cluster if e.username},
        "hosts": {_norm(e.host) for e in cluster if e.host},
        "source_ips": {e.source_ip for e in cluster if e.source_ip},
    }


def _matches_identity(event: Event, identity: dict[str, set[str]]) -> bool:
    return (
        (_norm(event.username) in identity["usernames"])
        or (_norm(event.host) in identity["hosts"])
        or (event.source_ip in identity["source_ips"])
    )


def _classify(cluster: list[Event]) -> tuple[str, int]:
    event_types = {e.event_type for e in cluster}
    severities = {e.severity for e in cluster}

    if "critical" in severities or "data_transfer" in event_types:
        return "Suspected ransomware / data exfiltration chain", 96
    if "privilege_escalation" in event_types:
        return "Suspected account compromise with privilege escalation", 80
    return "Suspicious activity requiring investigation", 55


def _lookup_threat_intel(db: Session, timeline: list[Event]) -> list[dict]:
    """Matches each event's source_ip and host against the shared Threat
    Intel Hub (app/threat_intel_hub.py) - a real, queryable, cross-tenant
    indicator table (seeded with one curated demo indicator, extendable
    with real feeds like URLhaus), replacing what used to be a single
    hardcoded IP in this file. Also tries a real live VirusTotal/AbuseIPDB
    lookup for anything not already known locally, if those API keys are
    configured (see lookup_many_with_live_fallback) - a no-op fallback to
    local-only matching when they aren't, so this behaves identically to
    before for anyone who hasn't set those keys."""
    candidates: list[str | None] = []
    for event in timeline:
        candidates.append(event.source_ip)
        candidates.append(event.host)

    hits = lookup_many_with_live_fallback(db, candidates)
    seen: set[str] = set()
    matches = []
    for value, indicator in hits.items():
        if indicator.indicator.lower() in seen:
            continue
        seen.add(indicator.indicator.lower())
        matches.append(
            {
                "indicator": value,
                "indicator_type": indicator.indicator_type,
                "verdict": indicator.verdict,
                "confidence": indicator.confidence,
                "source": indicator.source,
            }
        )
    return matches


def _assess_risk(cluster: list[Event], threat_intel: list[dict]) -> tuple[int, str, list[str]]:
    score = 0
    factors = []

    for event in cluster:
        score += SEVERITY_WEIGHTS.get(event.severity, 10)
        factors.append(f"{event.event_type} ({event.severity})")

    if threat_intel:
        score += 20
        factors.append("matched known-malicious threat intel")

    event_types = {e.event_type for e in cluster}
    if "data_transfer" in event_types and "privilege_escalation" in event_types:
        score += 15
        factors.append("privileged account used to exfiltrate data")

    score = min(score, 100)
    if score >= 80:
        level = "critical"
    elif score >= 60:
        level = "high"
    elif score >= 30:
        level = "medium"
    else:
        level = "low"

    return score, level, factors


def _recommend_actions(cluster: list[Event], risk_level: str) -> list[str]:
    actions = []
    event_types = {e.event_type for e in cluster}
    severities = {e.severity for e in cluster}
    users = _dedupe_case_insensitive(e.username for e in cluster if e.username)
    hosts = _dedupe_case_insensitive(e.host for e in cluster if e.host)
    ips = sorted({e.source_ip for e in cluster if e.source_ip})

    is_bas = any(et.startswith("bas_") for et in event_types)

    if "privilege_escalation" in event_types and users:
        actions.append(f"Disable and audit accounts: {', '.join(users)}")
    if ips:
        actions.append(f"Block source IP(s) at firewall/VPN: {', '.join(ips)}")
    # "high" alongside "critical": BAS-originated events (app/bas.py) top out
    # at "high" severity (there's no genuinely critical BAS technique), so
    # this rule never fired for a BAS incident before - only the generic
    # "open a ticket" line at the bottom did.
    if "critical" in severities or "high" in severities or "process_execution" in event_types:
        actions.append(f"Isolate host(s) from network: {', '.join(hosts)}")
    if "data_transfer" in event_types:
        actions.append("Force password reset for affected accounts and rotate database credentials")
    if "critical" in severities:
        actions.append("Verify offline/immutable backups before any remediation (ransomware indicator present)")
    if is_bas:
        actions.append(
            "Review the real command output from this technique execution to confirm whether it reflects "
            "an authorized simulation (Breach & Attack Simulation) or a genuine compromise"
        )
    if risk_level in ("high", "critical"):
        actions.append("Open incident ticket and notify security team immediately")

    return actions


def _generate_report(
    title: str,
    confidence: int,
    timeline: list[Event],
    cluster: list[Event],
    threat_intel: list[dict],
    risk_score: int,
    risk_level: str,
    factors: list[str],
    actions: list[str],
) -> str:
    lines = [
        f"# Incident Report: {title}",
        f"\n**Attack confidence:** {confidence}%",
        f"**Risk score:** {risk_score}/100 ({risk_level})",
        "\n## Timeline",
    ]
    for event in timeline:
        lines.append(f"- `{event.timestamp.isoformat()}` [{event.host}] {event.username or 'unknown'}: {event.message} ({event.source_type})")

    lines.append("\n## Alerts")
    for event in cluster:
        lines.append(f"- **{event.event_type}** ({event.severity}) — {event.message}")

    if threat_intel:
        lines.append("\n## Threat Intelligence")
        for match in threat_intel:
            lines.append(f"- `{match['indicator']}` ({match['indicator_type']}): {match['verdict']} — {match['confidence']}% confidence, source: {match['source']}")

    lines.append("\n## Risk Factors")
    for factor in factors:
        lines.append(f"- {factor}")

    lines.append("\n## Recommended Actions")
    for action in actions:
        lines.append(f"- [ ] {action}")

    return "\n".join(lines)


def run_correlation(db: Session, organization_id: int) -> list[Incident]:
    """Clusters not-yet-correlated events into incidents and persists them.
    Idempotent-ish: events already assigned to an incident are left alone,
    so re-running only picks up newly ingested activity. Scoped to one
    organization per call - two tenants' events must never be clustered
    into the same incident.

    Safe under concurrent calls: candidate events are atomically claimed via
    a single bulk UPDATE before any processing. The database's own row/table
    locking for that UPDATE statement (held for the rest of this
    transaction) means a second concurrent call's identical UPDATE simply
    can't see rows this call already claimed - it either blocks until this
    transaction finishes (Postgres row locks, SQLite's file lock) or, once
    this one commits, finds those rows no longer match `correlation_claim
    IS NULL`. Nothing is committed until the very end, so a crash mid-run
    rolls back the claim too and the events stay available for retry."""
    claim_id = str(uuid.uuid4())
    db.query(Event).filter(
        Event.organization_id == organization_id, Event.incident_id.is_(None), Event.correlation_claim.is_(None)
    ).update({Event.correlation_claim: claim_id}, synchronize_session=False)

    uncorrelated = db.query(Event).filter(Event.correlation_claim == claim_id).order_by(Event.timestamp).all()
    alerts = [e for e in uncorrelated if e.severity in ALERT_SEVERITIES]
    if not alerts:
        db.rollback()  # nothing to do - release the claim, this run is a no-op
        return []

    incidents: list[Incident] = []
    # A low-severity contextual event can match two different clusters' identity
    # sets at once (e.g. it shares a host with cluster A and a username with an
    # otherwise-unrelated cluster B). Track claimed events so it's attached to
    # exactly one incident instead of silently flipping to whichever cluster is
    # processed last while the earlier incident's report still describes it.
    # Doubles as the set of events this run actually resolved into an
    # incident, vs. ones that were claimed as candidates but matched nothing.
    claimed_ids: set[int] = set()

    for cluster in _cluster_alerts(alerts):
        identity = _identity(cluster)
        timeline = sorted(
            (e for e in uncorrelated if e.id not in claimed_ids and _matches_identity(e, identity)),
            key=lambda e: e.timestamp,
        )
        claimed_ids.update(e.id for e in timeline)

        title, confidence = _classify(cluster)
        threat_intel = _lookup_threat_intel(db, timeline)
        risk_score, risk_level, factors = _assess_risk(cluster, threat_intel)
        actions = _recommend_actions(cluster, risk_level)
        report = _generate_report(title, confidence, timeline, cluster, threat_intel, risk_score, risk_level, factors, actions)

        incident = Incident(
            organization_id=organization_id,
            title=title,
            confidence=confidence,
            risk_score=risk_score,
            risk_level=risk_level,
            priority=risk_level,
            risk_factors=factors,
            threat_intel=threat_intel,
            recommended_actions=actions,
            affected_hosts=_dedupe_case_insensitive(e.host for e in timeline),
            affected_users=_dedupe_case_insensitive(e.username for e in timeline if e.username),
            report=report,
        )
        db.add(incident)
        db.flush()

        for event in timeline:
            event.incident_id = incident.id

        store_embedding(db, organization_id, "incident", incident.id, f"{title}\n\n{report}")
        _notify_responders(db, organization_id, incident)
        _notify_slack(db, incident)
        incidents.append(incident)

    # Release the claim on any candidate that didn't end up matching a
    # cluster (e.g. a low-severity event unrelated to every alert in this
    # batch), so it's still eligible the next time /correlate runs.
    for event in uncorrelated:
        if event.id not in claimed_ids:
            event.correlation_claim = None

    db.commit()
    for incident in incidents:
        db.refresh(incident)

    return incidents


_RESPONDER_ROLES = ("owner", "admin", "soc_manager", "analyst")


def _notify_responders(db: Session, organization_id: int, incident: Incident) -> None:
    """New incidents page everyone with operational (non-read-only) access
    *in the same organization* - there's no assignee yet for a freshly-
    correlated incident, so everyone who could triage it gets notified.
    Must stay org-scoped: paging another tenant's staff would both leak
    this incident's existence/title to them and spam them with an alert
    they have no way to act on."""
    responders = (
        db.query(User)
        .filter(User.organization_id == organization_id, User.role.in_(_RESPONDER_ROLES), User.is_active.is_(True))
        .all()
    )
    for user in responders:
        db.add(Notification(
            user_id=user.id,
            message=f"New {incident.risk_level} incident: {incident.title}",
            incident_id=incident.id,
        ))


def _notify_slack(db: Session, incident: Incident) -> None:
    # Local import: app.slack_bot pulls in app.tasks -> app.agents.runner,
    # and correlation.py must stay importable standalone (tests import it
    # directly) without dragging in the whole Celery/agents chain at module
    # load time - see app/slack_bot.py's own docstring for why this never
    # raises regardless.
    from app.slack_bot import notify_new_incident

    try:
        notify_new_incident(db, incident)
    except Exception:
        pass
