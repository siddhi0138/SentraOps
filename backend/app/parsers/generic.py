from app.parsers.common import make_event, parse_timestamp

# Used when the source already reports roughly-normalized fields (REST API
# ingestion, CSV/JSON upload, or the attack simulator).
SEVERITY_FALLBACK = {
    "privilege_escalation": "high",
    "data_transfer": "high",
    "login_failed": "medium",
    "vpn_login_success": "medium",
    "process_execution": "medium",
}


def parse(raw: dict) -> dict:
    event_type = raw.get("event_type", "unknown")
    severity = raw.get("severity") or SEVERITY_FALLBACK.get(event_type, "low")

    return make_event(
        timestamp=parse_timestamp(raw.get("timestamp")),
        host=raw.get("host", "unknown-host"),
        username=raw.get("username") or raw.get("user"),
        source_ip=raw.get("source_ip"),
        event_type=event_type,
        severity=severity,
        message=raw.get("message") or raw.get("detail") or "",
    )
