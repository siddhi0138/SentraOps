import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db_models import Asset, Event, RawLog
from app.parsers import get_parser
from app.rag import store_embedding


def _serialize_raw(raw: Any) -> str:
    return raw if isinstance(raw, str) else json.dumps(raw)


def _as_utc_naive(dt: datetime) -> datetime:
    # SQLite drops tzinfo on datetime round-trips (Postgres doesn't), so a
    # freshly-parsed aware timestamp can't be compared against a value just
    # reloaded from the DB. Normalize everything to naive UTC to keep
    # dev (SQLite) and prod (Postgres) behaving the same.
    return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt


def _apply_sighting(asset: Asset, timestamp: datetime) -> None:
    asset.event_count += 1
    if timestamp > _as_utc_naive(asset.last_seen):
        asset.last_seen = timestamp
    if timestamp < _as_utc_naive(asset.first_seen):
        asset.first_seen = timestamp


def _upsert_asset(db: Session, organization_id: int, host: str, timestamp: datetime) -> None:
    # Hostnames are case-insensitive and the same physical host routinely
    # shows up with different casing across log sources (see correlation.py).
    # Scoped per-organization: two different customers can each have a host
    # named "DC01" without colliding (see db_models.Asset's composite index).
    timestamp = _as_utc_naive(timestamp)
    asset = (
        db.query(Asset)
        .filter(Asset.organization_id == organization_id, func.lower(Asset.host) == host.lower())
        .first()
    )
    if asset is not None:
        _apply_sighting(asset, timestamp)
        return

    # Race window: a concurrent request could insert this same host (maybe
    # in different casing) between the SELECT above and this INSERT. The
    # unique index on (organization_id, lower(host)) (see db_models.Asset)
    # turns that into a clean IntegrityError instead of a duplicate row. A
    # SAVEPOINT scopes the rollback to just this insert attempt, so the
    # rest of this ingest batch's pending Event/RawLog rows aren't
    # discarded too.
    try:
        with db.begin_nested():
            db.add(
                Asset(
                    organization_id=organization_id, host=host, first_seen=timestamp, last_seen=timestamp, event_count=1
                )
            )
            db.flush()
    except IntegrityError:
        asset = (
            db.query(Asset)
            .filter(Asset.organization_id == organization_id, func.lower(Asset.host) == host.lower())
            .one()
        )
        _apply_sighting(asset, timestamp)


def _event_embedding_text(event: Event) -> str:
    return f"[{event.host}] {event.username or 'unknown'} - {event.event_type} ({event.severity}): {event.message}"


def ingest(db: Session, organization_id: int, source_type: str, raw_items: list[Any]) -> tuple[list[Event], int]:
    """Parses+normalizes raw_items via the source_type's parser and persists both
    the raw payload (for audit/replay) and the normalized event. Unparseable
    items are skipped rather than failing the whole batch.

    Each event is also embedded for RAG search (app/rag.py). That's a
    synchronous CPU-bound call per event - fine at demo/dev ingestion
    volumes; a production-scale ingest path would move this to a background
    job instead of doing it inline per request."""
    parser = get_parser(source_type)
    events: list[Event] = []
    skipped = 0

    for raw in raw_items:
        raw_log = RawLog(organization_id=organization_id, source_type=source_type, payload=_serialize_raw(raw))
        db.add(raw_log)
        db.flush()

        try:
            normalized = parser(raw)
        except (ValueError, KeyError, TypeError):
            skipped += 1
            continue

        event = Event(organization_id=organization_id, raw_log_id=raw_log.id, source_type=source_type, **normalized)
        db.add(event)
        db.flush()
        events.append(event)
        _upsert_asset(db, organization_id, normalized["host"], normalized["timestamp"])
        store_embedding(db, organization_id, "event", event.id, _event_embedding_text(event))

    db.commit()
    for event in events:
        db.refresh(event)

    return events, skipped
