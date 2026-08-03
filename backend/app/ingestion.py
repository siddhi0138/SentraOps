import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db_models import Asset, Event, RawLog
from app.parsers import get_parser


def _serialize_raw(raw: Any) -> str:
    return raw if isinstance(raw, str) else json.dumps(raw)


def _as_utc_naive(dt: datetime) -> datetime:
    # SQLite drops tzinfo on datetime round-trips (Postgres doesn't), so a
    # freshly-parsed aware timestamp can't be compared against a value just
    # reloaded from the DB. Normalize everything to naive UTC to keep
    # dev (SQLite) and prod (Postgres) behaving the same.
    return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt


def _upsert_asset(db: Session, host: str, timestamp: datetime) -> None:
    # Hostnames are case-insensitive and the same physical host routinely
    # shows up with different casing across log sources (see correlation.py).
    timestamp = _as_utc_naive(timestamp)
    asset = db.query(Asset).filter(func.lower(Asset.host) == host.lower()).first()
    if asset is None:
        db.add(Asset(host=host, first_seen=timestamp, last_seen=timestamp, event_count=1))
        return

    asset.event_count += 1
    if timestamp > _as_utc_naive(asset.last_seen):
        asset.last_seen = timestamp
    if timestamp < _as_utc_naive(asset.first_seen):
        asset.first_seen = timestamp


def ingest(db: Session, source_type: str, raw_items: list[Any]) -> tuple[list[Event], int]:
    """Parses+normalizes raw_items via the source_type's parser and persists both
    the raw payload (for audit/replay) and the normalized event. Unparseable
    items are skipped rather than failing the whole batch."""
    parser = get_parser(source_type)
    events: list[Event] = []
    skipped = 0

    for raw in raw_items:
        raw_log = RawLog(source_type=source_type, payload=_serialize_raw(raw))
        db.add(raw_log)
        db.flush()

        try:
            normalized = parser(raw)
        except (ValueError, KeyError, TypeError):
            skipped += 1
            continue

        event = Event(raw_log_id=raw_log.id, source_type=source_type, **normalized)
        db.add(event)
        events.append(event)
        _upsert_asset(db, normalized["host"], normalized["timestamp"])

    db.commit()
    for event in events:
        db.refresh(event)

    return events, skipped
