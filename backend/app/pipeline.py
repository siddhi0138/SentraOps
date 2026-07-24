from app.models import LogEvent, Incident
from app.agents.detection import DetectionAgent
from app.agents.investigation import InvestigationAgent
from app.agents.threat_intel import ThreatIntelAgent
from app.agents.risk import RiskAgent
from app.agents.response import ResponseAgent
from app.agents.report import ReportAgent


def _incident_title(rules: set[str]) -> tuple[str, int]:
    if "shadow_copy_deletion" in rules or "data_transfer" in rules:
        return "Suspected ransomware / data exfiltration chain", 96
    if "privilege_escalation" in rules:
        return "Suspected account compromise with privilege escalation", 80
    if rules:
        return "Suspicious activity requiring investigation", 55
    return "No significant activity detected", 0


class SecurityPipeline:
    """Wires the six agents together into a single end-to-end investigation."""

    def __init__(self) -> None:
        self.detection = DetectionAgent()
        self.investigation = InvestigationAgent()
        self.threat_intel = ThreatIntelAgent()
        self.risk = RiskAgent()
        self.response = ResponseAgent()
        self.report = ReportAgent()

    def run(self, logs: list[LogEvent]) -> Incident:
        alerts = self.detection.run(logs)
        timeline = self.investigation.run(logs, alerts)
        threat_intel = self.threat_intel.run(alerts)
        risk = self.risk.run(alerts, threat_intel)
        actions = self.response.run(alerts, risk)
        title, confidence = _incident_title({a.rule for a in alerts})
        report_text = self.report.run(title, confidence, timeline, alerts, threat_intel, risk, actions)

        return Incident(
            title=title,
            confidence=confidence,
            alerts=alerts,
            timeline=timeline,
            threat_intel=threat_intel,
            risk=risk,
            recommended_actions=actions,
            affected_hosts=sorted({a.event.host for a in alerts}),
            affected_users=sorted({a.event.user for a in alerts}),
            report=report_text,
        )
