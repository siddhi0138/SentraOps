from datetime import datetime, timezone
from typing import TypedDict


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AgentMessage(TypedDict):
    agent: str
    content: str
    created_at: str


class AgentState(TypedDict, total=False):
    """Shared workspace every node in the coordinator graph reads from and
    writes to - this is the "GitHub PR for security investigations" the
    agents collaborate through instead of each starting from a blank prompt."""

    incident_id: int
    incident: dict
    timeline: list[dict]
    known_threat_intel: list[dict]
    known_risk_factors: list[str]
    known_recommended_actions: list[str]
    known_assets: list[dict]
    known_memory: dict
    known_graph_context: dict
    messages: list[AgentMessage]

    detection: dict
    investigation: dict
    threat_intel_findings: dict
    risk: dict
    response: dict
    report: dict

    stage: str
    error: str | None


def build_initial_state(
    incident,
    timeline: list[dict],
    assets: list[dict] | None = None,
    memory: dict | None = None,
    graph_context: dict | None = None,
) -> AgentState:
    return {
        "incident_id": incident.id,
        "incident": incident.to_summary_dict(),
        "timeline": timeline,
        "known_threat_intel": incident.threat_intel,
        "known_risk_factors": incident.risk_factors,
        "known_recommended_actions": incident.recommended_actions,
        "known_assets": assets or [],
        "known_memory": memory or {},
        "known_graph_context": graph_context or {},
        "messages": [],
        "stage": "starting",
        "error": None,
    }


def add_message(state: AgentState, agent: str, content: str) -> list[AgentMessage]:
    return state.get("messages", []) + [{"agent": agent, "content": content, "created_at": now_iso()}]


def format_timeline(timeline: list[dict]) -> str:
    """Renders the event list as compact text for an LLM prompt - the same
    shape every agent that needs to reason over raw events works from."""
    if not timeline:
        return "(no events in this incident's timeline)"
    lines = [
        f"{e['timestamp']} [{e['host']}] {e.get('username') or 'unknown'}: "
        f"{e['event_type']} ({e['severity']}) - {e['message']} (source: {e['source_type']})"
        for e in timeline
    ]
    return "\n".join(lines)


def format_memory_context(memory: dict) -> str:
    """Renders the cross-incident memory lookup (see agents/memory.py) as
    compact text - the same shape every agent that wants institutional
    history works from."""
    if not memory:
        return "(no prior history available)"

    parts = []

    if "similar_past_incidents" in memory:
        similar = memory["similar_past_incidents"] or []
        if similar:
            lines = []
            for s in similar:
                sim_pct = f"{round(s['similarity'] * 100)}%" if s.get("similarity") is not None else "unknown"
                summary = f" - prior finding: {s['prior_report_summary']}" if s.get("prior_report_summary") else ""
                lines.append(
                    f"- Incident #{s['incident_id']} \"{s['title']}\" ({s['risk_level']}, {s['status']}, "
                    f"{sim_pct} similar){summary}"
                )
            parts.append("Similar past incidents:\n" + "\n".join(lines))
        else:
            parts.append("No similar past incidents found.")

    for label, key in (("hosts", "repeat_hosts"), ("users", "repeat_users")):
        repeats = memory.get(key) or []
        if repeats:
            lines = [
                f"- Incident #{r['incident_id']} \"{r['title']}\" ({r['risk_level']}, {r['status']}) "
                f"also involved {', '.join(r['shared'])}"
                for r in repeats
            ]
            parts.append(f"Repeat {label} - prior incidents involving the same {label[:-1]}:\n" + "\n".join(lines))

    corrections = memory.get("recent_corrections") or []
    if corrections:
        lines = [
            f"- Incident #{c['incident_id']} \"{c['incident_title']}\" was flagged \"{c['rating'].replace('_', ' ')}\" "
            f"by an analyst: {c['note']}"
            for c in corrections
        ]
        parts.append(
            "Analyst feedback on past investigations - learn from these corrections, don't repeat the same "
            "mistake:\n" + "\n".join(lines)
        )

    return "\n\n".join(parts) if parts else "(no prior history available)"


def format_graph_context(graph_context: dict) -> str:
    """Renders the real Neo4j blast-radius traversal (see
    agents/graph_context.py) as compact text - genuinely different signal
    from format_memory_context's repeat-hosts/users: this reveals
    *indirect* multi-hop connections through the actual graph, not just an
    exact host/user match in another incident's flat field list."""
    if not graph_context or not graph_context.get("available"):
        return "(attack graph not available - not yet synced or Neo4j unreachable)"

    hosts = graph_context.get("connected_hosts") or []
    incident_count = graph_context.get("connected_incident_count", 0)
    if not hosts and not incident_count:
        return "No other hosts or incidents connected to this incident's hosts within 2 hops in the attack graph."

    parts = []
    if hosts:
        parts.append(f"Hosts reachable within 2 hops in the real attack graph (not necessarily in this incident): {', '.join(hosts)}.")
    if incident_count:
        parts.append(f"{incident_count} other incident(s) connect to this incident's hosts through the graph within 2 hops.")
    return " ".join(parts)
