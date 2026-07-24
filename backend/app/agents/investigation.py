from app.models import LogEvent, Alert


class InvestigationAgent:
    """Correlates alerts and raw logs into a single chronological incident timeline."""

    def run(self, logs: list[LogEvent], alerts: list[Alert]) -> list[LogEvent]:
        alerted_users = {a.event.user for a in alerts}
        alerted_hosts = {a.event.host for a in alerts}

        related = [e for e in logs if e.user in alerted_users or e.host in alerted_hosts]
        return sorted(related, key=lambda e: e.timestamp)
