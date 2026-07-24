from app.models import Alert, ThreatIntelMatch, RiskAssessment

SEVERITY_WEIGHTS = {"low": 5, "medium": 15, "high": 25, "critical": 35}


class RiskAgent:
    """Turns alerts + threat intel into a single business-risk score with an explanation."""

    def run(self, alerts: list[Alert], threat_intel: list[ThreatIntelMatch]) -> RiskAssessment:
        score = 0
        factors: list[str] = []

        for alert in alerts:
            score += SEVERITY_WEIGHTS.get(alert.severity, 10)
            factors.append(f"{alert.rule} ({alert.severity})")

        if threat_intel:
            score += 20
            factors.append("source IP matched known-malicious threat intel")

        if any(a.rule == "data_transfer" for a in alerts) and any(a.rule == "privilege_escalation" for a in alerts):
            score += 15
            factors.append("privileged account used to exfiltrate data")

        score = min(score, 100)

        if score >= 80:
            level = "critical"
        elif score >= 60:
            level = "high"
        elif score >= 30:
            level = "medium"
        else:
            level = "low"

        return RiskAssessment(score=score, level=level, factors=factors)
