from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.db import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="viewer")
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)


class RawLog(Base):
    """The untouched log payload exactly as it was ingested, for audit/replay."""

    __tablename__ = "raw_logs"

    id = Column(Integer, primary_key=True)
    source_type = Column(String(50), index=True, nullable=False)
    payload = Column(Text, nullable=False)
    received_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    events = relationship("Event", back_populates="raw_log")


class Event(Base):
    """Unified event schema every log source is normalized into."""

    __tablename__ = "events"

    id = Column(Integer, primary_key=True)
    raw_log_id = Column(Integer, ForeignKey("raw_logs.id"), nullable=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=True, index=True)

    timestamp = Column(DateTime(timezone=True), index=True, nullable=False)
    host = Column(String(255), index=True, nullable=False)
    username = Column(String(255), index=True, nullable=True)
    source_ip = Column(String(45), index=True, nullable=True)
    event_type = Column(String(50), index=True, nullable=False)
    severity = Column(String(20), index=True, nullable=False, default="low")
    message = Column(Text, nullable=False)
    source_type = Column(String(50), index=True, nullable=False)

    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    raw_log = relationship("RawLog", back_populates="events")
    incident = relationship("Incident", back_populates="events")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "host": self.host,
            "username": self.username,
            "source_ip": self.source_ip,
            "event_type": self.event_type,
            "severity": self.severity,
            "message": self.message,
            "source_type": self.source_type,
            "incident_id": self.incident_id,
        }


class Incident(Base):
    """A cluster of correlated events the correlation engine decided belong
    to the same attack, with enrichment/scoring/response/report attached."""

    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True)
    title = Column(String(255), nullable=False)
    confidence = Column(Integer, nullable=False, default=0)
    risk_score = Column(Integer, nullable=False, default=0)
    risk_level = Column(String(20), nullable=False, default="low")
    status = Column(String(20), nullable=False, default="open")

    risk_factors = Column(JSON, nullable=False, default=list)
    threat_intel = Column(JSON, nullable=False, default=list)
    recommended_actions = Column(JSON, nullable=False, default=list)
    affected_hosts = Column(JSON, nullable=False, default=list)
    affected_users = Column(JSON, nullable=False, default=list)
    report = Column(Text, nullable=False, default="")

    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    closed_at = Column(DateTime(timezone=True), nullable=True)

    events = relationship("Event", back_populates="incident", order_by="Event.timestamp")

    def to_summary_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "confidence": self.confidence,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "status": self.status,
            "affected_hosts": self.affected_hosts,
            "affected_users": self.affected_users,
            "event_count": len(self.events),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def to_detail_dict(self) -> dict:
        return {
            **self.to_summary_dict(),
            "risk_factors": self.risk_factors,
            "threat_intel": self.threat_intel,
            "recommended_actions": self.recommended_actions,
            "report": self.report,
            "timeline": [e.to_dict() for e in self.events],
        }
