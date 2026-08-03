from sqlalchemy.orm import Session

from app.db_models import Event, Incident, Notification, User

ALERT_SEVERITIES = {"medium", "high", "critical"}
SEVERITY_WEIGHTS = {"low": 5, "medium": 15, "high": 25, "critical": 35}

# Mock feed standing in for a real threat intel API (VirusTotal/AbuseIPDB)
# until milestone 2 wires one up.
KNOWN_BAD_IPS = {
    "185.220.101.45": ("known Tor exit node / ransomware C2 infrastructure", 98, "AbuseIPDB (mock)"),
}


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


def _lookup_threat_intel(timeline: list[Event]) -> list[dict]:
    matches = []
    seen_ips: set[str] = set()

    for event in timeline:
        ip = event.source_ip
        if ip and ip not in seen_ips and ip in KNOWN_BAD_IPS:
            verdict, confidence, source = KNOWN_BAD_IPS[ip]
            matches.append({"indicator": ip, "indicator_type": "ip", "verdict": verdict, "confidence": confidence, "source": source})
            seen_ips.add(ip)

    return matches


def _assess_risk(cluster: list[Event], threat_intel: list[dict]) -> tuple[int, str, list[str]]:
    score = 0
    factors = []

    for event in cluster:
        score += SEVERITY_WEIGHTS.get(event.severity, 10)
        factors.append(f"{event.event_type} ({event.severity})")

    if threat_intel:
        score += 20
        factors.append("source IP matched known-malicious threat intel")

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

    if "privilege_escalation" in event_types and users:
        actions.append(f"Disable and audit accounts: {', '.join(users)}")
    if ips:
        actions.append(f"Block source IP(s) at firewall/VPN: {', '.join(ips)}")
    if "critical" in severities or "process_execution" in event_types:
        actions.append(f"Isolate host(s) from network: {', '.join(hosts)}")
    if "data_transfer" in event_types:
        actions.append("Force password reset for affected accounts and rotate database credentials")
    if "critical" in severities:
        actions.append("Verify offline/immutable backups before any remediation (ransomware indicator present)")
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


def run_correlation(db: Session) -> list[Incident]:
    """Clusters not-yet-correlated events into incidents and persists them.
    Idempotent-ish: events already assigned to an incident are left alone,
    so re-running only picks up newly ingested activity."""
    uncorrelated = db.query(Event).filter(Event.incident_id.is_(None)).order_by(Event.timestamp).all()
    alerts = [e for e in uncorrelated if e.severity in ALERT_SEVERITIES]
    if not alerts:
        return []

    incidents: list[Incident] = []

    for cluster in _cluster_alerts(alerts):
        identity = _identity(cluster)
        timeline = sorted((e for e in uncorrelated if _matches_identity(e, identity)), key=lambda e: e.timestamp)

        title, confidence = _classify(cluster)
        threat_intel = _lookup_threat_intel(timeline)
        risk_score, risk_level, factors = _assess_risk(cluster, threat_intel)
        actions = _recommend_actions(cluster, risk_level)
        report = _generate_report(title, confidence, timeline, cluster, threat_intel, risk_score, risk_level, factors, actions)

        incident = Incident(
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

        _notify_responders(db, incident)
        incidents.append(incident)

    db.commit()
    for incident in incidents:
        db.refresh(incident)

    return incidents


def _notify_responders(db: Session, incident: Incident) -> None:
    """New incidents page every admin/analyst - there's no assignee yet for a
    freshly-correlated incident, so everyone who could triage it gets notified."""
    responders = db.query(User).filter(User.role.in_(("admin", "analyst")), User.is_active.is_(True)).all()
    for user in responders:
        db.add(Notification(
            user_id=user.id,
            message=f"New {incident.risk_level} incident: {incident.title}",
            incident_id=incident.id,
        ))
