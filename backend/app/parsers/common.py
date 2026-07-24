from datetime import datetime, timezone

from dateutil import parser as dateutil_parser


def parse_timestamp(value, default: datetime | None = None) -> datetime:
    if isinstance(value, datetime):
        return value
    return dateutil_parser.parse(str(value), default=default or datetime.now(timezone.utc))


def make_event(
    *,
    timestamp: datetime,
    host: str,
    event_type: str,
    message: str,
    username: str | None = None,
    source_ip: str | None = None,
    severity: str = "low",
) -> dict:
    return {
        "timestamp": timestamp,
        "host": host,
        "username": username,
        "source_ip": source_ip,
        "event_type": event_type,
        "severity": severity,
        "message": message,
    }
