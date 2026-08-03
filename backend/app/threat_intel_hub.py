import ipaddress
from datetime import datetime, timezone

from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db_models import Incident, ThreatIndicator
from app.graph import _process_graph_result, get_driver
from app.plugins.connectors.urlhaus import fetch_records


def indicator_type_of(value: str) -> str:
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        return "domain"


def upsert_indicator(
    db: Session,
    *,
    indicator: str,
    indicator_type: str,
    verdict: str,
    confidence: int,
    source: str,
    tags: str | None = None,
) -> ThreatIndicator:
    """Case-insensitive get-or-update, same race-safe SAVEPOINT/IntegrityError
    pattern as ingestion.py's asset upsert - a concurrent sync of the same
    indicator is a real (if rare) possibility once this is dispatched from
    more than one place, and the unique index on lower(indicator) makes the
    race a clean IntegrityError instead of a duplicate row."""
    now = datetime.now(timezone.utc)
    existing = db.query(ThreatIndicator).filter(func.lower(ThreatIndicator.indicator) == indicator.lower()).first()
    if existing:
        existing.verdict = verdict
        existing.confidence = confidence
        existing.source = source
        existing.tags = tags
        existing.last_seen = now
        return existing

    try:
        with db.begin_nested():
            row = ThreatIndicator(
                indicator=indicator,
                indicator_type=indicator_type,
                verdict=verdict,
                confidence=confidence,
                source=source,
                tags=tags,
                first_seen=now,
                last_seen=now,
            )
            db.add(row)
            db.flush()
        return row
    except IntegrityError:
        return db.query(ThreatIndicator).filter(func.lower(ThreatIndicator.indicator) == indicator.lower()).one()


def sync_urlhaus(db: Session, limit: int = 100) -> int:
    """Pulls the real URLhaus feed (app/plugins/connectors/urlhaus.py's
    fetch_records(), the same real data its log-ingestion connector uses)
    and upserts each reported host as a threat indicator. Distinct job
    from that connector: the connector produces Events for one org's log
    stream, this populates the platform-wide shared indicator table every
    org's correlation engine matches against."""
    records = fetch_records(limit=limit)
    count = 0
    for record in records:
        host = record["host"]
        upsert_indicator(
            db,
            indicator=host,
            indicator_type=indicator_type_of(host),
            verdict=f"{record['threat']} ({record['url_status']})" + (f" - tags: {record['tags']}" if record["tags"] else ""),
            confidence=90 if record["url_status"] == "online" else 60,
            source="URLhaus (abuse.ch)",
            tags=record["tags"] or None,
        )
        count += 1
    db.commit()
    return count


def lookup_many(db: Session, values: list[str | None]) -> dict[str, ThreatIndicator]:
    """Batch case-insensitive lookup, keyed by the original (not lowercased)
    input value - callers pass a mix of event source_ips/hosts and want to
    match each back to whichever indicators actually hit."""
    lowered = {v.lower(): v for v in values if v}
    if not lowered:
        return {}
    rows = db.query(ThreatIndicator).filter(func.lower(ThreatIndicator.indicator).in_(lowered.keys())).all()
    return {lowered[row.indicator.lower()]: row for row in rows}


def _looks_like_external_indicator(value: str) -> bool:
    """Filters out internal asset names (FINANCE-PC-21, db-server-03)
    before ever attempting a live lookup - those aren't real public
    IPs/domains VirusTotal or AbuseIPDB could ever have data on, and
    calling anyway would just burn through the free-tier rate limit on
    guaranteed 404s. A real public IP always qualifies; a bare hostname
    only qualifies if it has a domain-shaped tail (an alphabetic TLD-like
    last segment, e.g. "evil-domain.com") - internal hostnames essentially
    never do."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    if "." not in value:
        return False
    tld = value.rsplit(".", 1)[-1]
    return tld.isalpha() and len(tld) >= 2


def lookup_many_with_live_fallback(db: Session, values: list[str | None]) -> dict[str, ThreatIndicator]:
    """Same as lookup_many, but for any candidate not already known
    locally, tries a real live lookup (VirusTotal/AbuseIPDB - see
    app/threat_intel_providers.py) if an API key is configured, upserting
    a genuine hit so it's cached in the shared indicator table and never
    re-fetched from the live API again. A strict superset of lookup_many's
    existing behavior: with no keys configured (the default), this
    produces identical results to calling lookup_many alone."""
    from app.threat_intel_providers import live_lookup

    hits = lookup_many(db, values)
    known_lower = {h.indicator.lower() for h in hits.values()}

    for value in {v for v in values if v}:
        if value.lower() in known_lower or not _looks_like_external_indicator(value):
            continue
        live = live_lookup(value, indicator_type_of(value))
        if not live:
            continue
        row = upsert_indicator(
            db,
            indicator=value,
            indicator_type=indicator_type_of(value),
            verdict=live["verdict"],
            confidence=live["confidence"],
            source=live["source"],
        )
        hits[value] = row
        known_lower.add(value.lower())

    return hits


def search(db: Session, q: str | None = None, indicator_type: str | None = None, limit: int = 50) -> list[ThreatIndicator]:
    query = db.query(ThreatIndicator)
    if q:
        query = query.filter(ThreatIndicator.indicator.ilike(f"%{q}%"))
    if indicator_type:
        query = query.filter(ThreatIndicator.indicator_type == indicator_type)
    return query.order_by(ThreatIndicator.last_seen.desc()).limit(limit).all()


def _ensure_indicator_graph_constraints(session) -> None:
    """Same auto-commit-before-write-transaction requirement as
    graph.py's _ensure_constraints - see that function's docstring for why
    (confirmed against a real Neo4j instance, not a guess)."""
    session.run("CREATE CONSTRAINT indicator_value IF NOT EXISTS FOR (i:Indicator) REQUIRE i.value IS UNIQUE")
    session.run("CREATE CONSTRAINT threat_tag_name IF NOT EXISTS FOR (t:Tag) REQUIRE t.name IS UNIQUE")
    session.run("CREATE CONSTRAINT threat_source_name IF NOT EXISTS FOR (s:Source) REQUIRE s.name IS UNIQUE")


def _rebuild_indicator_graph_tx(tx, indicator_rows: list[dict], tag_edges: list[dict], match_rows: list[dict]) -> None:
    # Scoped by label, not organization_id - Indicator/Tag/Source are
    # shared platform data (see ThreatIndicator's own docstring), not one
    # org's graph, so this must never touch Host/User/IP/Incident nodes
    # graph.py's own resync manages.
    tx.run("MATCH (n) WHERE n:Indicator OR n:Tag OR n:Source DETACH DELETE n")

    tx.run(
        """
        UNWIND $rows AS row
        MERGE (i:Indicator {value: row.value})
        SET i.indicator_type = row.indicator_type, i.verdict = row.verdict,
            i.confidence = row.confidence, i.source = row.source
        MERGE (s:Source {name: row.source})
        MERGE (i)-[:REPORTED_BY]->(s)
        """,
        rows=indicator_rows,
    )

    if tag_edges:
        tx.run(
            """
            UNWIND $rows AS row
            MATCH (i:Indicator {value: row.value})
            MERGE (t:Tag {name: row.tag})
            MERGE (i)-[:TAGGED_AS]->(t)
            """,
            rows=tag_edges,
        )

    if match_rows:
        # Only links to an Incident node that already exists (created by
        # that org's own graph.resync_graph() call) - if that org hasn't
        # synced its attack graph yet, this MATCH simply finds nothing and
        # no edge is created, the same graceful "not synced yet" behavior
        # the Attack Graph feature already has elsewhere.
        tx.run(
            """
            UNWIND $rows AS row
            MATCH (i:Indicator {value: row.value})
            MATCH (c:Incident {id: row.incident_id})
            MERGE (i)-[:MATCHED_IN]->(c)
            """,
            rows=match_rows,
        )


def resync_indicator_graph(db: Session, driver=None) -> dict:
    """Rebuilds the shared threat-intel relationship graph (Indicator/Tag/
    Source, plus real MATCHED_IN links into whichever orgs' own incident
    graphs already exist) from Postgres - same full-resync-not-incremental
    strategy as graph.resync_graph(), for the same reason (simpler, fine at
    this project's data volume). The Indicator/Tag/Source layer is
    deliberately not organization_id-scoped, matching ThreatIndicator's own
    not-tenant-data design - but MATCHED_IN edges are only ever *read* back
    re-scoped by organization_id (see get_indicator_graph), so nothing
    cross-tenant is actually exposed even though the shared nodes carry
    every org's matches in storage."""
    driver = driver or get_driver()

    indicators = db.query(ThreatIndicator).all()
    indicator_rows = []
    tag_edges = []
    for ind in indicators:
        value = ind.indicator.lower()
        indicator_rows.append(
            {
                "value": value,
                "indicator_type": ind.indicator_type,
                "verdict": ind.verdict,
                "confidence": ind.confidence,
                "source": ind.source,
            }
        )
        for tag in (ind.tags or "").split(","):
            tag = tag.strip().lower()
            if tag:
                tag_edges.append({"value": value, "tag": tag})

    # Filtered in Python, not `Incident.threat_intel != []` in SQL - JSON
    # column equality comparisons are exactly the kind of thing that
    # behaves differently across SQLite/Postgres (this project has hit
    # that class of bug enough times - see executive.py's own trend query -
    # to default to Python-side filtering for anything JSON-shaped).
    match_rows = []
    for incident in db.query(Incident).all():
        for match in incident.threat_intel or []:
            indicator_value = (match.get("indicator") or "").lower()
            if indicator_value:
                match_rows.append({"value": indicator_value, "incident_id": incident.id})

    with driver.session() as session:
        _ensure_indicator_graph_constraints(session)
        session.execute_write(_rebuild_indicator_graph_tx, indicator_rows, tag_edges, match_rows)

    return {"indicators": len(indicator_rows), "tag_links": len(tag_edges), "incident_matches": len(match_rows)}


def get_indicator_graph(organization_id: int, limit: int = 300, driver=None) -> dict:
    """The shared threat-intel relationship graph: which indicators share
    tags/sources with each other, plus which have actually matched in
    *this* organization's own incidents. MATCHED_IN is re-scoped by
    organization_id right here in the query, even though Indicator/Tag/
    Source nodes themselves are shared platform data - see
    resync_indicator_graph's docstring for why that split is safe."""
    driver = driver or get_driver()
    with driver.session() as session:
        result = session.run(
            """
            MATCH (a:Indicator)-[r:TAGGED_AS|REPORTED_BY]->(b)
            RETURN a, r, b
            UNION
            MATCH (a:Indicator)-[r:MATCHED_IN]->(b:Incident {organization_id: $org_id})
            RETURN a, r, b
            LIMIT $limit
            """,
            org_id=organization_id,
            limit=limit,
        )
        return _process_graph_result(result)
