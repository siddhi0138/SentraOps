from app.parsers.common import make_event, parse_timestamp

PRIVILEGE_ESCALATION_EVENTS = {"CreateUser", "AttachUserPolicy", "AddUserToGroup", "CreateAccessKey", "PutUserPolicy"}
DATA_TRANSFER_EVENTS = {"GetObject", "PutObject"}


def parse(raw: dict) -> dict:
    event_name = raw.get("eventName", "UnknownEvent")
    username = (raw.get("userIdentity") or {}).get("userName")
    error_code = raw.get("errorCode")

    if event_name == "ConsoleLogin":
        success = (raw.get("responseElements") or {}).get("ConsoleLogin") == "Success"
        event_type = "login_success" if success else "login_failed"
        severity = "low" if success else "medium"
    elif event_name in PRIVILEGE_ESCALATION_EVENTS:
        event_type, severity = "privilege_escalation", "high"
    elif error_code:
        event_type, severity = "access_denied", "medium"
    elif event_name in DATA_TRANSFER_EVENTS:
        event_type, severity = "data_transfer", "low"
    else:
        event_type, severity = "cloudtrail_event", "low"

    message = event_name + (f" ({error_code})" if error_code else "")

    return make_event(
        timestamp=parse_timestamp(raw.get("eventTime")),
        host="aws",
        username=username,
        source_ip=raw.get("sourceIPAddress"),
        event_type=event_type,
        severity=severity,
        message=message,
    )
