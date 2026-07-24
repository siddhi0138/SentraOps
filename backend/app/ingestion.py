import json
from typing import Any

from sqlalchemy.orm import Session

from app.db_models import Event, RawLog
from app.parsers import get_parser


def _serialize_raw(raw: Any) -> str:
    return raw if isinstance(raw, str) else json.dumps(raw)


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

    db.commit()
    for event in events:
        db.refresh(event)

    return events, skipped
