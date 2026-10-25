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


# --- self-healing: retry the backfill in the background -----------------------------
# A write that couldn't be embedded (service asleep or rate-limited) is saved without its
# vector. Rather than wait for someone to call /rag/reindex, retry in the background after
# the service has had time to wake up.

import logging
import os
import threading
import time

logger = logging.getLogger(__name__)

_in_flight: set[int] = set()
_in_flight_lock = threading.Lock()


def has_missing(db: Session, organization_id: int) -> bool:
    return bool(_missing(db, Event, "event", organization_id, 1) or _missing(db, Incident, "incident", organization_id, 1))


def _backfill_loop(organization_id: int, delays, session_factory, sleep=time.sleep) -> None:
    try:
        for delay in delays:
            sleep(delay)
            db = session_factory()
            try:
                if not has_missing(db, organization_id):
                    return
                backfill_missing_embeddings(db, organization_id)
            except Exception:
                logger.warning("Background embedding backfill failed", exc_info=True)
            finally:
                db.close()
    finally:
        with _in_flight_lock:
            _in_flight.discard(organization_id)


def schedule_backfill(organization_id: int, delays=(20, 60, 180)) -> bool:
    """Starts a background thread that retries filling in missing vectors after each delay,
    stopping as soon as nothing is missing. At most one per organization at a time.
    Returns whether a thread was started."""
    if os.environ.get("EMBEDDING_BACKFILL_RETRY", "true").lower() != "true":
        return False
    with _in_flight_lock:
        if organization_id in _in_flight:
            return False
        _in_flight.add(organization_id)

    from app.db import SessionLocal

    threading.Thread(target=_backfill_loop, args=(organization_id, delays, SessionLocal), daemon=True).start()
    return True
