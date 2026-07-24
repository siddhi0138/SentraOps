import re

from app.parsers.common import make_event, parse_timestamp

LINE_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>\S+?)(?:\[\d+\])?:\s+(?P<message>.*)$"
)
FAILED_RE = re.compile(r"Failed password for(?: invalid user)? (?P<user>\S+) from (?P<ip>[\d.]+)")
ACCEPTED_RE = re.compile(r"Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+)")
SUDO_RE = re.compile(r"^(?P<user>\S+)\s*:.*COMMAND=")


def parse(raw: str) -> dict:
    match = LINE_RE.match(raw.strip())
    if not match:
        raise ValueError(f"Unrecognized syslog line: {raw!r}")

    fields = match.groupdict()
    message = fields["message"]

    username = None
    source_ip = None
    event_type, severity = "syslog_event", "low"

    if failed := FAILED_RE.search(message):
        username, source_ip = failed["user"], failed["ip"]
        event_type, severity = "login_failed", "medium"
    elif accepted := ACCEPTED_RE.search(message):
        username, source_ip = accepted["user"], accepted["ip"]
        event_type, severity = "login_success", "low"
    elif fields["process"] == "sudo" and (sudo := SUDO_RE.search(message)):
        username = sudo["user"]
        event_type, severity = "privilege_escalation", "medium"

    return make_event(
        # syslog has no year field; assume current year.
        timestamp=parse_timestamp(fields["timestamp"]),
        host=fields["host"],
        username=username,
        source_ip=source_ip,
        event_type=event_type,
        severity=severity,
        message=message,
    )
