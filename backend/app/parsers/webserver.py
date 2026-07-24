import re

from app.parsers.common import make_event, parse_timestamp

# Apache/Nginx combined log format.
LINE_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
)


def parse(raw: str) -> dict:
    match = LINE_RE.match(raw.strip())
    if not match:
        raise ValueError(f"Unrecognized web server log line: {raw!r}")

    fields = match.groupdict()
    status = int(fields["status"])

    if status >= 500:
        event_type, severity = "http_error", "high"
    elif status in (401, 403):
        event_type, severity = "auth_failed", "medium"
    elif status == 404:
        event_type, severity = "http_not_found", "low"
    else:
        event_type, severity = "http_request", "low"

    # CLF timestamp uses ':' between date and time (e.g. 24/Jul/2026:09:17:10 +0000).
    date_part, _, time_part = fields["timestamp"].partition(":")

    return make_event(
        timestamp=parse_timestamp(f"{date_part} {time_part}"),
        host="webserver",
        username=None,
        source_ip=fields["ip"],
        event_type=event_type,
        severity=severity,
        message=f'{fields["method"]} {fields["path"]} -> {status}',
    )
