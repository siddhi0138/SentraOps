from app.models import Alert, RiskAssessment


class ResponseAgent:
    """Recommends containment and remediation actions based on the risk assessment."""

    def run(self, alerts: list[Alert], risk: RiskAssessment) -> list[str]:
        actions: list[str] = []
        rules = {a.rule for a in alerts}
        users = {a.event.user for a in alerts}
        hosts = {a.event.host for a in alerts}

        if "privilege_escalation" in rules:
            actions.append(f"Disable and audit accounts: {', '.join(sorted(users))}")
        if any(a.event.source_ip for a in alerts):
            ips = sorted({a.event.source_ip for a in alerts if a.event.source_ip})
            actions.append(f"Block source IP(s) at firewall/VPN: {', '.join(ips)}")
        if "encoded_powershell" in rules or "shadow_copy_deletion" in rules:
            actions.append(f"Isolate host(s) from network: {', '.join(sorted(hosts))}")
        if "data_transfer" in rules:
            actions.append("Force password reset for affected accounts and rotate database credentials")
        if "shadow_copy_deletion" in rules:
            actions.append("Verify offline/immutable backups before any remediation (ransomware indicator present)")
        if risk.level in ("high", "critical"):
            actions.append("Open incident ticket and notify security team immediately")

        return actions
