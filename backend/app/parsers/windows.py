from app.parsers.common import make_event, parse_timestamp

# (event_type, severity) per Windows Security Event ID.
EVENT_ID_MAP = {
    4624: ("login_success", "low"),
    4625: ("login_failed", "medium"),
    4720: ("privilege_escalation", "high"),  # new (often admin) account created
    4732: ("privilege_escalation", "high"),  # added to a security-enabled group
    4688: ("process_execution", "low"),
}
RANSOMWARE_INDICATORS = ("vssadmin", "shadow", "cipher.exe", "bcdedit")


def parse(raw: dict) -> dict:
    event_id = int(raw["EventID"])
    event_type, severity = EVENT_ID_MAP.get(event_id, ("windows_event", "low"))

    command_line = (raw.get("CommandLine") or "").lower()
    if event_id == 4688 and "powershell" in command_line and "-enc" in command_line:
        event_type, severity = "process_execution", "high"
    elif event_id == 4688 and any(i in command_line for i in RANSOMWARE_INDICATORS):
        event_type, severity = "process_execution", "critical"

    username = raw.get("TargetUserName") or raw.get("SubjectUserName")

    return make_event(
        timestamp=parse_timestamp(raw.get("TimeCreated") or raw.get("timestamp")),
        host=raw.get("Computer", "unknown-host"),
        username=username,
        source_ip=raw.get("IpAddress"),
        event_type=event_type,
        severity=severity,
        message=raw.get("Message") or f"Windows Event ID {event_id} for {username}",
    )
