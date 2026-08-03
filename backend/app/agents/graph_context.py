from neo4j.exceptions import Neo4jError, ServiceUnavailable

from app.db_models import Incident
from app.graph import get_entity_blast_radius


def build_graph_context(incident: Incident) -> dict:
    """Real Neo4j blast-radius traversal over this incident's affected
    hosts - genuinely different from agents/memory.py's repeat-hosts/users
    check: that's a flat Postgres lookup for an *exact* host/user match in
    another incident's affected_hosts/users list, while this walks the
    real graph and surfaces *indirect* connections a flat field-equality
    query can never see (host A shares a user with host B, host B shares
    an IP with an incident on host C - two hops away, not a direct match).
    Best-effort: if the graph hasn't been synced yet or Neo4j is
    unreachable, this returns an empty/unavailable context rather than
    failing the investigation - the same "silently optional" behavior the
    Attack Graph UI already has for an unsynced graph."""
    hosts = incident.affected_hosts or []
    own_hosts_lower = {h.lower() for h in hosts}
    reachable_hosts: set[str] = set()
    reachable_incidents: set[int] = set()

    # Bounded, not one round-trip per affected host without limit - an
    # incident spanning many hosts shouldn't mean unbounded Neo4j calls
    # before an agent can even start reasoning.
    for host in hosts[:5]:
        try:
            subgraph = get_entity_blast_radius("host", host, incident.organization_id, hops=2)
        except (Neo4jError, ServiceUnavailable):
            return {"available": False, "connected_hosts": [], "connected_incident_count": 0}

        for node in subgraph["nodes"]:
            if node.get("label") == "Host" and node.get("name") and node["name"].lower() not in own_hosts_lower:
                reachable_hosts.add(node["name"])
            elif node.get("label") == "Incident" and node.get("id") is not None and node["id"] != incident.id:
                reachable_incidents.add(node["id"])

    return {
        "available": True,
        "connected_hosts": sorted(reachable_hosts)[:10],
        "connected_incident_count": len(reachable_incidents),
    }
