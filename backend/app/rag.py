import logging
import re

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.db_models import Embedding
from app.embeddings import embed_text, embed_texts

logger = logging.getLogger(__name__)

_STOPWORDS = {"the", "and", "for", "with", "that", "this", "from", "what", "which", "are", "was", "were", "have", "has", "had", "how", "why", "when", "who", "any", "all", "about", "into", "there", "their", "been", "does", "did", "show", "tell"}


def store_embeddings(db: Session, organization_id: int, items: list[tuple[str, int | None, str]]) -> bool:
    """Batch version of store_embedding: items are (content_type, content_id, text).
    Makes one embedding call for the whole list instead of one per item.
    Returns False (after logging) if the embeddings service was unavailable."""
    items = [item for item in items if item[2] and item[2].strip()]
    if not items:
        return True
    try:
        vectors = embed_texts([text for _, _, text in items])
    except Exception:
        # The embeddings service is a free third-party hop that can rate-limit
        # or sleep. Saving the data matters more than its search vector, which
        # reindex.backfill_missing_embeddings adds later.
        logger.warning("Embedding service unavailable; saving %d item(s) without search vectors", len(items), exc_info=True)
        return False
    for (content_type, content_id, text), vector in zip(items, vectors):
        db.add(
            Embedding(
                organization_id=organization_id, content_type=content_type, content_id=content_id, text=text,
                vector=vector,
            )
        )
    return True


def store_embedding(db: Session, organization_id: int, content_type: str, content_id: int | None, text: str) -> bool:
    return store_embeddings(db, organization_id, [(content_type, content_id, text)])


def _to_result(row: Embedding, score: float | None = None) -> dict:
    return {
        "content_type": row.content_type,
        "content_id": row.content_id,
        "text": row.text,
        "score": score,
    }


def _like(token: str) -> str:
    return "%" + token.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _keyword_search(db: Session, organization_id: int, query: str, content_type: str | None, k: int) -> list[dict]:
    """Plain keyword matching over events, incidents and stored knowledge text.
    Used only when the embeddings service can't turn the query into a vector, so
    search keeps answering (less smartly) instead of failing. Results have the same
    shape as vector search; `score` is the fraction of query words that matched."""
    # Imported here because these modules import this one at load time.
    from app.db_models import Event, Incident
    from app.ingestion import _event_embedding_text

    tokens = [t for t in dict.fromkeys(re.findall(r"[a-z0-9_.\-]{3,}", query.lower())) if t not in _STOPWORDS][:8]
    if not tokens:
        return []

    candidates: list[tuple[str, int | None, str]] = []
    if content_type in (None, "event"):
        conditions = []
        for t in tokens:
            pattern = _like(t)
            conditions += [Event.message.ilike(pattern, escape="\\"), Event.host.ilike(pattern, escape="\\"),
                           Event.username.ilike(pattern, escape="\\"), Event.event_type.ilike(pattern, escape="\\")]
        for e in db.query(Event).filter(Event.organization_id == organization_id, or_(*conditions)).order_by(Event.timestamp.desc()).limit(200):
            candidates.append(("event", e.id, _event_embedding_text(e)))
    if content_type in (None, "incident"):
        conditions = []
        for t in tokens:
            pattern = _like(t)
            conditions += [Incident.title.ilike(pattern, escape="\\"), Incident.report.ilike(pattern, escape="\\")]
        for i in db.query(Incident).filter(Incident.organization_id == organization_id, or_(*conditions)).order_by(Incident.created_at.desc()).limit(100):
            candidates.append(("incident", i.id, f"{i.title}\n\n{i.report}"))
    if content_type in (None, "knowledge_chunk"):
        conditions = [Embedding.text.ilike(_like(t), escape="\\") for t in tokens]
        for row in db.query(Embedding).filter(Embedding.organization_id == organization_id, Embedding.content_type == "knowledge_chunk", or_(*conditions)).limit(100):
            candidates.append(("knowledge_chunk", row.content_id, row.text))

    scored = []
    for ct, cid, text in candidates:
        lowered = text.lower()
        scored.append((sum(1 for t in tokens if t in lowered) / len(tokens), ct, cid, text))
    scored.sort(key=lambda r: r[0], reverse=True)
    return [{"content_type": ct, "content_id": cid, "text": text, "score": score} for score, ct, cid, text in scored[:k]]


def search(db: Session, organization_id: int, query: str, content_type: str | None = None, k: int = 5) -> list[dict]:
    """Semantic search over stored embeddings. Postgres uses pgvector's
    indexed cosine_distance() operator; SQLite (dev only) falls back to a
    brute-force cosine similarity scan in Python - fine for the row counts
    a dev/demo database has, not meant to scale.

    Always scoped to one organization - this is the RAG grounding for
    chat/incident-explain/similar-incidents, so an unscoped query here
    would leak another tenant's event/incident text into an answer, not
    just their metadata."""
    try:
        query_vector = embed_text(query)
    except Exception:
        logger.warning("Embedding service unavailable; falling back to keyword search", exc_info=True)
        return _keyword_search(db, organization_id, query, content_type, k)

    base_query = db.query(Embedding).filter(Embedding.organization_id == organization_id)
    if content_type:
        base_query = base_query.filter(Embedding.content_type == content_type)

    dialect = db.get_bind().dialect.name

    if dialect == "postgresql":
        distance = Embedding.vector.cosine_distance(query_vector)
        rows = base_query.add_columns(distance.label("distance")).order_by(distance).limit(k).all()
        # cosine_distance is 1 - cosine_similarity; report similarity (higher
        # = more relevant) so both dialects' `score` mean the same thing.
        return [_to_result(row, score=1 - dist) for row, dist in rows]

    import numpy as np

    candidates = base_query.all()
    if not candidates:
        return []

    qv = np.array(query_vector)
    scored = []
    for row in candidates:
        v = np.array(row.vector)
        similarity = float(np.dot(qv, v) / (np.linalg.norm(qv) * np.linalg.norm(v) + 1e-9))
        scored.append((similarity, row))
    scored.sort(key=lambda pair: pair[0], reverse=True)

    return [_to_result(row, score=similarity) for similarity, row in scored[:k]]
