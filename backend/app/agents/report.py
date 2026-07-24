from app.models import LogEvent, Alert, ThreatIntelMatch, RiskAssessment


class ReportAgent:
    """Turns the pipeline's findings into a human-readable executive incident report."""

    def run(
        self,
        title: str,
        confidence: int,
        timeline: list[LogEvent],
        alerts: list[Alert],
        threat_intel: list[ThreatIntelMatch],
        risk: RiskAssessment,
        actions: list[str],
    ) -> str:
        lines = [
            f"# Incident Report: {title}",
            f"\n**Attack confidence:** {confidence}%",
            f"**Risk score:** {risk.score}/100 ({risk.level})",
            "\n## Timeline",
        ]
        for event in timeline:
            lines.append(f"- `{event.timestamp}` [{event.host}] {event.user}: {event.detail}")

        lines.append("\n## Alerts")
        for alert in alerts:
            lines.append(f"- **{alert.rule}** ({alert.severity}) — {alert.note}")

        if threat_intel:
            lines.append("\n## Threat Intelligence")
            for ti in threat_intel:
                lines.append(f"- `{ti.indicator}` ({ti.indicator_type}): {ti.verdict} — {ti.confidence}% confidence, source: {ti.source}")

        lines.append("\n## Risk Factors")
        for factor in risk.factors:
            lines.append(f"- {factor}")

        lines.append("\n## Recommended Actions")
        for action in actions:
            lines.append(f"- [ ] {action}")

        return "\n".join(lines)
