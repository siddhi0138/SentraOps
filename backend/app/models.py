from typing import Optional
from pydantic import BaseModel


class LogEvent(BaseModel):
    timestamp: str
    host: str
    user: str
    event_type: str
    detail: str
    source_ip: Optional[str] = None


class Alert(BaseModel):
    event: LogEvent
    rule: str
    severity: str  # low | medium | high | critical
    note: str


class ThreatIntelMatch(BaseModel):
    indicator: str
    indicator_type: str  # ip | hash | domain
    verdict: str
    confidence: int
    source: str


class RiskAssessment(BaseModel):
    score: int
    level: str
    factors: list[str]


class Incident(BaseModel):
    title: str
    confidence: int
    alerts: list[Alert]
    timeline: list[LogEvent]
    threat_intel: list[ThreatIntelMatch]
    risk: RiskAssessment
    recommended_actions: list[str]
    affected_hosts: list[str]
    affected_users: list[str]
    report: str
