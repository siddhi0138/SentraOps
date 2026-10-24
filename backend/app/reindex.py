"""Fills in search vectors that were skipped while the embeddings service was
unavailable (see rag.store_embeddings, which saves the data and logs instead of
failing the request)."""

from sqlalchemy import and_, exists
from sqlalchemy.orm import Session

from app.db_models import Embedding, Event, Incident
from app.ingestion import _event_embedding_text
from app.rag import store_embeddings


def _missing(db: Session, model, content_type: str, organization_id: int, limit: int) -> list:
    already_embedded = exists().where(
        and_(
            Embedding.organization_id == organization_id,
            Embedding.content_type == content_type,
            Embedding.content_id == model.id,
        )
    )
    return db.query(model).filter(model.organization_id == organization_id, ~already_embedded).limit(limit).all()


def backfill_missing_embeddings(db: Session, organization_id: int, limit: int = 50) -> int:
    """Embeds up to `limit` events and `limit` incidents that have no vector yet,
    in a single embedding call, and returns how many were stored. Returns 0 if the
    embeddings service is still unavailable; safe to call repeatedly."""
    events = _missing(db, Event, "event", organization_id, limit)
    incidents = _missing(db, Incident, "incident", organization_id, limit)

    items = [("event", e.id, _event_embedding_text(e)) for e in events]
    items += [("incident", i.id, f"{i.title}\n\n{i.report}") for i in incidents]
    if not items:
        return 0

    if not store_embeddings(db, organization_id, items):
        db.rollback()
        return 0
    db.commit()
    return len(items)
