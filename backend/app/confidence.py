from sqlalchemy.orm import Session

from app.db_models import Event
from app.graph import get_driver

SEMANTIC_STRONG_THRESHOLD = 0.55
STRUCTURAL_STRONG_THRESHOLD = 0.5


def _org_key(organization_id: int, value: str) -> str:
    """Must exactly match app/graph.py's own org_key format - that's the
    real uniqueness key on every Host/User node, not the display name."""
    return f"{organization_id}:{value}"


def _is_structurally_corroborated(session, organization_id: int, content_type: str | None, content_id: int | None, host_by_event_id: dict) -> bool | None:
    """Whether one RAG evidence item's underlying entity is actually present
    *and connected* in this org's real attack graph - i.e. independently
    confirmed by the graph-sync pipeline (app/graph.py), not just retrieved
    because its text embedding happened to be a semantic near-miss for the
    question. Returns None (not False) when the item can't be checked at
    all, so the caller excludes it from the ratio instead of counting an
    unrelated content type as a strike against corroboration."""
    if content_type == "incident" and content_id:
        record = session.run(
            "MATCH (c:Incident {id: $id, organization_id: $org_id})-[]-() RETURN count(*) AS degree",
            id=content_id,
            org_id=organization_id,
        ).single()
        return bool(record and record["degree"] > 0)

    if content_type == "event" and content_id:
        host = host_by_event_id.get(content_id)
        if not host:
            return None
        record = session.run(
            "MATCH (h:Host {org_key: $org_key})-[]-() RETURN count(*) AS degree",
            org_key=_org_key(organization_id, host.lower()),
        ).single()
        return bool(record and record["degree"] > 0)

    return None


def compute_dual_evidence_confidence(db: Session, organization_id: int, evidence: list[dict], driver=None) -> dict:
    """Cross-validates two *independent* evidence channels behind an
    AI-generated answer, instead of trusting either alone:

      1. Semantic evidence - the RAG retrieval's own cosine-similarity
         score (app/rag.py): does the retrieved text look relevant.
      2. Structural evidence - whether that same evidence item's entity is
         actually present and connected in the org's real Neo4j attack
         graph (app/graph.py): is it corroborated by independently-derived
         relational data, not just word similarity.

    A text chunk can score high on semantic similarity while describing an
    entity graph-sync never actually connected to anything (stale data, an
    isolated one-off event) - and a chunk can be a well-connected entity but
    a weak semantic match for the actual question. Requiring *both* signals
    to agree before calling an answer "high confidence" is the point:
    either signal alone is what a plain RAG system or a plain graph system
    already gives you.

    Fails open, not closed: if Neo4j is unreachable, structural_corroboration
    comes back 0.0 (unverified, not "verified false"), so confidence can
    still fall back to "medium" purely on the semantic signal rather than
    the whole chat feature breaking because the graph is down.
    """
    scored = [e for e in evidence if e.get("score") is not None]
    semantic_score = sum(e["score"] for e in scored) / len(scored) if scored else 0.0

    event_ids = [e["content_id"] for e in evidence if e.get("content_type") == "event" and e.get("content_id")]
    host_by_event_id: dict[int, str] = {}
    if event_ids:
        rows = db.query(Event.id, Event.host).filter(Event.id.in_(event_ids)).all()
        host_by_event_id = {row.id: row.host for row in rows}

    checked: list[bool] = []
    try:
        driver = driver or get_driver()
        with driver.session() as session:
            for e in evidence:
                corroborated = _is_structurally_corroborated(
                    session, organization_id, e.get("content_type"), e.get("content_id"), host_by_event_id
                )
                if corroborated is not None:
                    checked.append(corroborated)
    except Exception:
        checked = []

    structural_corroboration = sum(checked) / len(checked) if checked else 0.0

    semantic_strong = semantic_score >= SEMANTIC_STRONG_THRESHOLD
    structural_strong = structural_corroboration >= STRUCTURAL_STRONG_THRESHOLD

    if semantic_strong and structural_strong:
        confidence = "high"
    elif semantic_strong or structural_strong:
        confidence = "medium"
    else:
        confidence = "low"

    return {
        "confidence": confidence,
        "semantic_score": round(semantic_score, 3),
        "structural_corroboration": round(structural_corroboration, 3),
        "evidence_checked": len(checked),
    }
