from app.parsers.common import make_event, parse_timestamp


def parse(raw: dict) -> dict:
    action = (raw.get("action") or "").upper()
    event_type = "firewall_deny" if action == "DENY" else "firewall_allow"
    severity = "medium" if action == "DENY" else "low"

    return make_event(
        timestamp=parse_timestamp(raw.get("timestamp")),
        host=raw.get("dst_host") or raw.get("dst_ip", "unknown-host"),
        username=None,
        source_ip=raw.get("src_ip"),
        event_type=event_type,
        severity=severity,
        message=f'{action} {raw.get("protocol", "?")} {raw.get("src_ip")} -> {raw.get("dst_ip")}:{raw.get("dst_port")}',
    )
