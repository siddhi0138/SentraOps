import os

from neo4j import GraphDatabase
from sqlalchemy.orm import Session

from app.db_models import Event, Incident

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "sentraops")

_driver = None

# entity_type (as accepted by the API) -> (Neo4j label, unique display property name)
ENTITY_LABELS = {"host": ("Host", "name"), "user": ("User", "name"), "ip": ("IP", "address")}


def get_driver():
    """Lazily-created singleton, swappable via reset_driver() - tests pass
    a fake/mock driver directly into each function instead of touching
    this global, the same reason app/tasks.py's session factory is
    swappable rather than hardcoded."""
    global _driver
    if _driver is None:
        _driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    return _driver


def reset_driver() -> None:
    global _driver
    if _driver is not None:
        _driver.close()
        _driver = None


def _org_key(organization_id: int, value: str) -> str:
    """Neo4j Community Edition only supports single-property uniqueness
    constraints (composite/multi-property constraints are Enterprise-only),
    so tenant isolation can't be a `(organization_id, name)` composite key
    at the constraint level. Instead, the *real* uniqueness key baked into
    every Host/User/IP node is this synthetic "<org_id>:<value>" string -
    two different organizations' "DC01" hosts get two entirely separate
    nodes, never merged into one, without depending on Enterprise features."""
    return f"{organization_id}:{value}"


def _node_key(node) -> str:
    """The app-level id used to build the frontend's node/edge graph shape -
    distinct from org_key above (Neo4j's own MERGE identity). A single API
    response is always for one already-scoped organization, so this only
    needs to be unique *within* that response, not globally."""
    label = next(iter(node.labels))
    prop = {"Host": "name", "User": "name", "IP": "address", "Incident": "id", "Indicator": "value"}.get(label, "name")
    return f"{label}:{node[prop]}"


def _node_to_dict(node) -> dict:
    props = {k: v for k, v in dict(node).items() if k != "org_key"}
    return {"key": _node_key(node), "label": next(iter(node.labels)), **props}


def _process_graph_result(result) -> dict:
    """Every query below returns (a, r, b) triples - this is the one place
    that turns that into a deduplicated node list + edge list the frontend
    can render as a network graph."""
    nodes: dict[str, dict] = {}
    edges = []
    for record in result:
        a, r, b = record["a"], record["r"], record["b"]
        nodes[_node_key(a)] = _node_to_dict(a)
        nodes[_node_key(b)] = _node_to_dict(b)
        edges.append({"from": _node_key(a), "to": _node_key(b), "type": r.type, **dict(r)})
    return {"nodes": list(nodes.values()), "edges": edges}


def _ensure_constraints(session) -> None:
    """Neo4j forbids mixing schema modification (CREATE CONSTRAINT) with a
    write query in the same transaction (Neo.ClientError.Transaction.
    ForbiddenDueToTransactionType, confirmed by actually running this
    against a real Neo4j instance) - constraints must run in their own
    auto-commit statements, separate from the execute_write transaction
    that does the DETACH DELETE + rebuild. Constrained on org_key (see
    _org_key), not the display name/address - see that function for why."""
    session.run("CREATE CONSTRAINT host_org_key IF NOT EXISTS FOR (h:Host) REQUIRE h.org_key IS UNIQUE")
    session.run("CREATE CONSTRAINT user_org_key IF NOT EXISTS FOR (u:User) REQUIRE u.org_key IS UNIQUE")
    session.run("CREATE CONSTRAINT ip_org_key IF NOT EXISTS FOR (i:IP) REQUIRE i.org_key IS UNIQUE")
    session.run("CREATE CONSTRAINT incident_id IF NOT EXISTS FOR (c:Incident) REQUIRE c.id IS UNIQUE")


def _rebuild_graph_tx(tx, organization_id: int, incident_rows: list[dict], event_rows: list[dict]) -> None:
    # Scoped delete, not a global wipe - resyncing organization A's graph
    # must never touch organization B's already-synced nodes.
    tx.run("MATCH (n {organization_id: $org_id}) DETACH DELETE n", org_id=organization_id)

    tx.run(
        """
        UNWIND $rows AS row
        MERGE (c:Incident {id: row.id})
        SET c.organization_id = $org_id, c.title = row.title, c.risk_level = row.risk_level, c.status = row.status
        """,
        rows=incident_rows,
        org_id=organization_id,
    )

    tx.run(
        """
        UNWIND $rows AS row
        MERGE (h:Host {org_key: row.host_org_key})
        SET h.organization_id = $org_id, h.name = row.host
        WITH h, row
        MATCH (c:Incident {id: row.incident_id})
        MERGE (h)-[:PART_OF]->(c)
        """,
        rows=event_rows,
        org_id=organization_id,
    )

    user_rows = [r for r in event_rows if r["user"]]
    if user_rows:
        tx.run(
            """
            UNWIND $rows AS row
            MERGE (u:User {org_key: row.user_org_key})
            SET u.organization_id = $org_id, u.name = row.user
            WITH u, row
            MATCH (h:Host {org_key: row.host_org_key}), (c:Incident {id: row.incident_id})
            MERGE (u)-[r1:ACCESSED]->(h)
              ON CREATE SET r1.count = 1
              ON MATCH SET r1.count = r1.count + 1
            MERGE (u)-[:PART_OF]->(c)
            """,
            rows=user_rows,
            org_id=organization_id,
        )

    ip_rows = [r for r in event_rows if r["ip"]]
    if ip_rows:
        tx.run(
            """
            UNWIND $rows AS row
            MERGE (ip:IP {org_key: row.ip_org_key})
            SET ip.organization_id = $org_id, ip.address = row.ip
            WITH ip, row
            MATCH (h:Host {org_key: row.host_org_key}), (c:Incident {id: row.incident_id})
            MERGE (ip)-[r1:CONNECTED_TO]->(h)
              ON CREATE SET r1.count = 1
              ON MATCH SET r1.count = r1.count + 1
            MERGE (ip)-[:PART_OF]->(c)
            """,
            rows=ip_rows,
            org_id=organization_id,
        )


def resync_graph(db: Session, organization_id: int, driver=None) -> dict:
    """Rebuilds one organization's attack graph from Postgres, which stays
    the source of truth - Neo4j is a derived, read-optimized view for the
    graph-shaped questions the relational schema answers badly (blast
    radius of a host/user/IP, shared-entity paths across incidents). A
    full resync of just this org (not incremental sync-on-ingest, and never
    touching other orgs' already-synced nodes) is simpler and doesn't
    couple the hot ingestion path to a second database - fine at this
    project's data volume; a real high-throughput deployment would stream
    changes instead."""
    driver = driver or get_driver()

    incidents = db.query(Incident).filter(Incident.organization_id == organization_id).all()
    events = (
        db.query(Event)
        .filter(Event.organization_id == organization_id, Event.incident_id.isnot(None))
        .all()
    )

    incident_rows = [{"id": i.id, "title": i.title, "risk_level": i.risk_level, "status": i.status} for i in incidents]
    event_rows = [
        {
            "host": e.host.lower(),
            "host_org_key": _org_key(organization_id, e.host.lower()),
            "user": e.username.lower() if e.username else None,
            "user_org_key": _org_key(organization_id, e.username.lower()) if e.username else None,
            "ip": e.source_ip,
            "ip_org_key": _org_key(organization_id, e.source_ip) if e.source_ip else None,
            "incident_id": e.incident_id,
        }
        for e in events
    ]

    with driver.session() as session:
        _ensure_constraints(session)
        session.execute_write(_rebuild_graph_tx, organization_id, incident_rows, event_rows)

    return {"incidents": len(incident_rows), "events_processed": len(event_rows)}


def get_incident_subgraph(incident_id: int, organization_id: int, driver=None) -> dict:
    """Every Host/User/IP tied to one incident, plus the edges between
    them - what the "Attack Graph" tab on an incident renders. The
    Postgres-side org check already happened before this is called (see
    main.py's _get_scoped_or_404), but the Cypher itself is *also* scoped -
    defense in depth, not redundant, since this function has no other way
    to know the caller was already authorized for this incident."""
    driver = driver or get_driver()
    with driver.session() as session:
        result = session.run(
            """
            MATCH (n {organization_id: $org_id})-[:PART_OF]->(c:Incident {id: $id, organization_id: $org_id})
            WITH collect(DISTINCT n) + collect(DISTINCT c) AS nodes
            UNWIND nodes AS a
            MATCH (a)-[r]->(b) WHERE b IN nodes
            RETURN DISTINCT a, r, b
            """,
            id=incident_id,
            org_id=organization_id,
        )
        return _process_graph_result(result)


def get_entity_blast_radius(entity_type: str, value: str, organization_id: int, hops: int = 2, driver=None) -> dict:
    """Everything reachable from one host/user/IP within N hops, across
    every incident it appears in - the actual "attack graph" query: does
    this host/user/IP connect to other incidents through a shared entity,
    revealing a bigger pattern than any single incident shows on its own.
    Traversal itself is org-scoped (every hop stays within organization_id),
    not just the starting node - a shared physical host name across two
    unrelated tenants must never let one tenant's blast radius wander into
    the other's graph."""
    if entity_type not in ENTITY_LABELS:
        raise ValueError(f"Unknown entity type: {entity_type}")
    label, prop = ENTITY_LABELS[entity_type]
    hops = max(1, min(hops, 4))
    lookup_value = value.lower() if entity_type != "ip" else value
    start_org_key = _org_key(organization_id, lookup_value)

    driver = driver or get_driver()
    with driver.session() as session:
        result = session.run(
            f"""
            MATCH (start:{label} {{org_key: $org_key}})
            OPTIONAL MATCH (start)-[*1..{hops}]-(connected {{organization_id: $org_id}})
            WITH start, collect(DISTINCT connected) AS connected_nodes
            WITH [start] + connected_nodes AS nodes
            UNWIND nodes AS a
            MATCH (a)-[r]->(b) WHERE b IN nodes
            RETURN DISTINCT a, r, b
            """,
            org_key=start_org_key,
            org_id=organization_id,
        )
        return _process_graph_result(result)


def get_full_graph(organization_id: int, limit: int = 300, driver=None) -> dict:
    """A capped view of the whole attack graph - the general explorer."""
    driver = driver or get_driver()
    with driver.session() as session:
        result = session.run(
            "MATCH (a {organization_id: $org_id})-[r]->(b) RETURN a, r, b LIMIT $limit",
            org_id=organization_id,
            limit=limit,
        )
        return _process_graph_result(result)
