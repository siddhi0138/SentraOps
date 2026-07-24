from app.models import LogEvent, Alert

SUSPICIOUS_EVENT_TYPES = {
    "privilege_escalation": ("high", "New admin/privileged account created"),
    "data_transfer": ("high", "Large or unusual data transfer"),
}

RANSOMWARE_INDICATORS = ("vssadmin", "shadow", "cipher.exe", "bcdedit")


class DetectionAgent:
    """Flags suspicious individual log events using simple, explainable rules."""

    def run(self, logs: list[LogEvent]) -> list[Alert]:
        alerts: list[Alert] = []
        failed_logins: dict[str, int] = {}

        for event in logs:
            if event.event_type == "login_failed":
                failed_logins[event.user] = failed_logins.get(event.user, 0) + 1
                if failed_logins[event.user] >= 2:
                    alerts.append(Alert(
                        event=event,
                        rule="repeated_failed_logins",
                        severity="medium",
                        note=f"{failed_logins[event.user]} failed logins for {event.user}",
                    ))

            elif event.event_type == "vpn_login_success" and event.source_ip:
                alerts.append(Alert(
                    event=event,
                    rule="login_after_failures",
                    severity="medium",
                    note="Successful login immediately following failed attempts",
                ))

            elif event.event_type == "process_execution" and "powershell" in event.detail.lower() and "-enc" in event.detail.lower():
                alerts.append(Alert(
                    event=event,
                    rule="encoded_powershell",
                    severity="high",
                    note="Encoded PowerShell command execution (common post-exploitation technique)",
                ))

            elif event.event_type == "process_execution" and any(i in event.detail.lower() for i in RANSOMWARE_INDICATORS):
                alerts.append(Alert(
                    event=event,
                    rule="shadow_copy_deletion",
                    severity="critical",
                    note="Shadow copy / backup deletion — classic ransomware pre-encryption step",
                ))

            elif event.event_type in SUSPICIOUS_EVENT_TYPES:
                severity, note = SUSPICIOUS_EVENT_TYPES[event.event_type]
                alerts.append(Alert(event=event, rule=event.event_type, severity=severity, note=note))

        return alerts
