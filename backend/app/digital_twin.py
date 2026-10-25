from sqlalchemy.orm import Session

from app.ai import chat_json
from app.db_models import Asset
from app.graph import get_entity_blast_radius

CRITICALITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def simulate_compromise(db: Session, entity_type: str, value: str, organization_id: int, hops: int = 2) -> dict:
    """Real 'what happens if this is compromised' simulation - a read-only
    walk of the actual Neo4j attack graph outward from the given entity
    (app/graph.py's blast-radius query, already used by the Attack Graph
    feature), cross-referenced against this org's real Asset criticality
    data. Not a fabricated scenario tree: every reachable host/user/incident
    in the result genuinely exists in this org's data - the only thing
    "simulated" is that none of it is executed against production, exactly
    what a digital twin means."""
    graph = get_entity_blast_radius(entity_type, value, organization_id, hops=hops)

    reachable_hosts = sorted({n["name"] for n in graph["nodes"] if n.get("label") == "Host" and n.get("name")})
    reachable_users = sorted({n["name"] for n in graph["nodes"] if n.get("label") == "User" and n.get("name")})
    reachable_incidents = [n for n in graph["nodes"] if n.get("label") == "Incident"]

    assets_by_host_lower = {}
    if reachable_hosts:
        assets = db.query(Asset).filter(Asset.organization_id == organization_id, Asset.host.in_(reachable_hosts)).all()
        assets_by_host_lower = {a.host.lower(): a for a in assets}

    affected_assets = []
    impact_score = 0
    for host in reachable_hosts:
        asset = assets_by_host_lower.get(host.lower())
        criticality = asset.criticality if asset else "unknown"
        impact_score += CRITICALITY_WEIGHT.get(criticality, 1)
        affected_assets.append(
            {
                "host": host,
                "criticality": criticality,
                "department": asset.department if asset else None,
                "owner": asset.owner if asset else None,
            }
        )
    affected_assets.sort(key=lambda a: CRITICALITY_WEIGHT.get(a["criticality"], 1), reverse=True)

    # Percentage of the theoretical worst case (every reachable host being
    # "critical") - a bounded, comparable number rather than a raw sum that
    # means nothing on its own across simulations of different sizes.
    max_possible = len(reachable_hosts) * CRITICALITY_WEIGHT["critical"] if reachable_hosts else 0
    business_impact_pct = round(100 * impact_score / max_possible) if max_possible else 0

    return {
        "entity_type": entity_type,
        "entity_value": value,
        "hops": hops,
        "reachable_hosts": len(reachable_hosts),
        "reachable_users": len(reachable_users),
        "related_incidents": len(reachable_incidents),
        "affected_assets": affected_assets,
        "business_impact_score": impact_score,
        "business_impact_pct": business_impact_pct,
        "graph": graph,
    }


_TWIN_SYSTEM_PROMPT = """You are SentraOps, running a security "digital twin" simulation: a \
read-only, offline prediction of what would happen if one specific user, \
host, or IP address were compromised - nothing is executed against any real \
system. You are given a real blast-radius graph traversal (the actual \
hosts/users/incidents this entity connects to in this organization's data) \
and real asset criticality/ownership data. Predict plausible lateral \
movement, business impact, and a rough recovery estimate, grounded strictly \
in the real entities given - never invent a host, user, or incident not \
present in the data.

Respond with ONLY a valid JSON object (no markdown fences, no extra text). \
CRITICAL: every value must be a properly double-quoted JSON string (or an \
array of double-quoted strings) - never write a value without surrounding \
quotes, no matter how long.

Exact keys required:
- "lateral_movement_narrative": a JSON string, 2-4 sentences describing a plausible attack path across the real reachable hosts/users given, in order.
- "affected_systems": a JSON array of short JSON strings, each a real host name from the data given, most business-critical first.
- "business_impact": a JSON string, 1-2 sentences on business impact grounded in the real criticality/department/owner data given.
- "estimated_recovery": a JSON string, a rough recovery time estimate (e.g. "a few hours" to "several days") with a one-sentence reason tied to the real blast radius size.
- "confidence": a JSON string, exactly one of "low", "medium", or "high" - "low" if the blast radius has very few reachable entities, "high" if it spans multiple hosts/users/incidents with real criticality data attached.

Base everything strictly on the data given. Do not invent hosts, users, incidents, or criticality levels not present in the data.

Example of the exact shape required (values illustrative only, not real data):
{"lateral_movement_narrative": "An attacker starting on FINANCE-PC-21 could pivot to DB-SERVER-03 via the shared user account, then reach the finance database.", \
"affected_systems": ["DB-SERVER-03", "FINANCE-PC-21"], \
"business_impact": "DB-SERVER-03 is marked critical and owned by the Finance department, so compromise would directly threaten financial data.", \
"estimated_recovery": "Likely 1-2 days, given only two hosts and one shared account are involved.", \
"confidence": "medium"}"""


def _format_simulation_for_prompt(simulation: dict) -> str:
    lines = [
        f"Simulated compromise of {simulation['entity_type']} '{simulation['entity_value']}', {simulation['hops']}-hop blast radius.",
        f"Reachable hosts: {simulation['reachable_hosts']}, reachable users: {simulation['reachable_users']}, related incidents: {simulation['related_incidents']}.",
    ]
    if simulation["affected_assets"]:
        lines.append("Affected hosts (most critical first):")
        for a in simulation["affected_assets"]:
            lines.append(f"  - {a['host']}: criticality={a['criticality']}, department={a['department'] or 'unknown'}, owner={a['owner'] or 'unknown'}")
    else:
        lines.append("No reachable hosts found in the graph for this entity.")
    lines.append(f"Business impact score: {simulation['business_impact_pct']}% of theoretical worst case.")
    return "\n".join(lines)


def generate_twin_narrative(simulation: dict) -> dict:
    return chat_json(_TWIN_SYSTEM_PROMPT, _format_simulation_for_prompt(simulation), max_tokens=500, feature="digital_twin_narrative")
