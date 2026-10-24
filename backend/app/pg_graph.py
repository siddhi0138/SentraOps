"""The attack graph served straight from Postgres.

app/graph.py keeps a Neo4j copy of the graph, but every node and edge in it is
derived from the incidents and events tables. When Neo4j isn't reachable (a free
Aura instance that was paused or deleted, a bad NEO4J_URI) these functions
rebuild the same graph in memory from Postgres and answer the same queries, so
the Attack Graph, blast-radius and Digital Twin features keep working.

Results use the same shape as the Neo4j versions: {"nodes": [...], "edges": [...]}.
"""

from collections import defaultdict, deque

from sqlalchemy.orm import Session

from app.db_models import Event, Incident

_ENTITY_LABELS = {"host": "Host", "user": "User", "ip": "IP"}


def _build(db: Session, organization_id: int) -> tuple[dict[str, dict], dict[tuple[str, str, str], dict]]:
    """Nodes by key and edges by (from, to, type), mirroring _rebuild_graph_tx in
    graph.py: Host/User/IP -PART_OF-> Incident, User -ACCESSED-> Host and
    IP -CONNECTED_TO-> Host (both counting how many events produced them)."""
    nodes: dict[str, dict] = {}
    edges: dict[tuple[str, str, str], dict] = {}

    incidents = db.query(Incident).filter(Incident.organization_id == organization_id).all()
    for i in incidents:
        key = f"Incident:{i.id}"
        nodes[key] = {
            "key": key, "label": "Incident", "organization_id": organization_id,
            "id": i.id, "title": i.title, "risk_level": i.risk_level, "status": i.status,
        }

    def link(source: str, target: str, kind: str, counted: bool = False) -> None:
        edge = edges.get((source, target, kind))
        if edge is None:
            edge = {"from": source, "to": target, "type": kind}
            if counted:
                edge["count"] = 0
            edges[(source, target, kind)] = edge
        if counted:
            edge["count"] += 1

    events = db.query(Event).filter(Event.organization_id == organization_id, Event.incident_id.isnot(None)).all()
    for e in events:
        incident_key = f"Incident:{e.incident_id}"
        if incident_key not in nodes:
            continue

        host = e.host.lower()
        host_key = f"Host:{host}"
        nodes.setdefault(host_key, {"key": host_key, "label": "Host", "organization_id": organization_id, "name": host})
        link(host_key, incident_key, "PART_OF")

        if e.username:
            name = e.username.lower()
            user_key = f"User:{name}"
            nodes.setdefault(user_key, {"key": user_key, "label": "User", "organization_id": organization_id, "name": name})
            link(user_key, host_key, "ACCESSED", counted=True)
            link(user_key, incident_key, "PART_OF")

        if e.source_ip:
            ip_key = f"IP:{e.source_ip}"
            nodes.setdefault(ip_key, {"key": ip_key, "label": "IP", "organization_id": organization_id, "address": e.source_ip})
            link(ip_key, host_key, "CONNECTED_TO", counted=True)
            link(ip_key, incident_key, "PART_OF")

    return nodes, edges


def _only_used_nodes(nodes: dict[str, dict], edges: list[dict]) -> dict:
    used = {end for edge in edges for end in (edge["from"], edge["to"])}
    return {"nodes": [nodes[key] for key in nodes if key in used], "edges": edges}


def incident_subgraph(db: Session, incident_id: int, organization_id: int) -> dict:
    nodes, edges = _build(db, organization_id)
    incident_key = f"Incident:{incident_id}"
    if incident_key not in nodes:
        return {"nodes": [], "edges": []}

    members = {incident_key} | {e["from"] for e in edges.values() if e["to"] == incident_key and e["type"] == "PART_OF"}
    inside = [e for e in edges.values() if e["from"] in members and e["to"] in members]
    return _only_used_nodes(nodes, inside)


def entity_blast_radius(db: Session, entity_type: str, value: str, organization_id: int, hops: int = 2) -> dict:
    if entity_type not in _ENTITY_LABELS:
        raise ValueError(f"Unknown entity type: {entity_type}")
    hops = max(1, min(hops, 4))
    lookup = value if entity_type == "ip" else value.lower()
    start = f"{_ENTITY_LABELS[entity_type]}:{lookup}"

    nodes, edges = _build(db, organization_id)
    if start not in nodes:
        return {"nodes": [], "edges": []}

    neighbours: dict[str, set[str]] = defaultdict(set)
    for source, target, _kind in edges:
        neighbours[source].add(target)
        neighbours[target].add(source)

    reached = {start}
    frontier = deque([(start, 0)])
    while frontier:
        current, depth = frontier.popleft()
        if depth == hops:
            continue
        for nxt in neighbours[current]:
            if nxt not in reached:
                reached.add(nxt)
                frontier.append((nxt, depth + 1))

    inside = [e for e in edges.values() if e["from"] in reached and e["to"] in reached]
    return _only_used_nodes(nodes, inside)


def full_graph(db: Session, organization_id: int, limit: int = 300) -> dict:
    nodes, edges = _build(db, organization_id)
    return _only_used_nodes(nodes, list(edges.values())[:limit])


def counts(db: Session, organization_id: int) -> dict:
    """What a resync would have loaded, for /graph/sync's response."""
    incidents = db.query(Incident).filter(Incident.organization_id == organization_id).count()
    events = db.query(Event).filter(Event.organization_id == organization_id, Event.incident_id.isnot(None)).count()
    return {"incidents": incidents, "events_processed": events}


def indicator_graph(db: Session, organization_id: int, limit: int = 300) -> dict:
    """The shared threat-intel graph (Indicator -REPORTED_BY-> Source,
    Indicator -TAGGED_AS-> Tag) plus this organization's own incident matches
    (Indicator -MATCHED_IN-> Incident), the same shape get_indicator_graph returns."""
    from app.db_models import ThreatIndicator

    nodes: dict[str, dict] = {}
    tag_and_source_edges: list[dict] = []
    match_edges: list[dict] = []

    for ind in db.query(ThreatIndicator).all():
        value = ind.indicator.lower()
        indicator_key = f"Indicator:{value}"
        nodes[indicator_key] = {
            "key": indicator_key, "label": "Indicator", "value": value, "indicator_type": ind.indicator_type,
            "verdict": ind.verdict, "confidence": ind.confidence, "source": ind.source,
        }
        source_key = f"Source:{ind.source}"
        nodes.setdefault(source_key, {"key": source_key, "label": "Source", "name": ind.source})
        tag_and_source_edges.append({"from": indicator_key, "to": source_key, "type": "REPORTED_BY"})
        for tag in sorted({t.strip().lower() for t in (ind.tags or "").split(",") if t.strip()}):
            tag_key = f"Tag:{tag}"
            nodes.setdefault(tag_key, {"key": tag_key, "label": "Tag", "name": tag})
            tag_and_source_edges.append({"from": indicator_key, "to": tag_key, "type": "TAGGED_AS"})

    seen_matches: set[tuple[str, int]] = set()
    for incident in db.query(Incident).filter(Incident.organization_id == organization_id).all():
        for match in incident.threat_intel or []:
            value = (match.get("indicator") or "").lower()
            indicator_key = f"Indicator:{value}"
            if not value or indicator_key not in nodes or (indicator_key, incident.id) in seen_matches:
                continue
            seen_matches.add((indicator_key, incident.id))
            incident_key = f"Incident:{incident.id}"
            nodes[incident_key] = {
                "key": incident_key, "label": "Incident", "organization_id": organization_id, "id": incident.id,
                "title": incident.title, "risk_level": incident.risk_level, "status": incident.status,
            }
            match_edges.append({"from": indicator_key, "to": incident_key, "type": "MATCHED_IN"})

    return _only_used_nodes(nodes, (tag_and_source_edges + match_edges)[:limit])
