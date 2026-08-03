from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text, func
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
    # Set atomically by the correlation engine to claim a batch of candidate
    # events before processing, so two concurrent /correlate calls can't both
    # grab the same events. Not exposed via to_dict() - purely internal.
    correlation_claim = Column(String(36), nullable=True, index=True)

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
    priority = Column(String(20), nullable=False, default="medium")
    assignee_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    risk_factors = Column(JSON, nullable=False, default=list)
    threat_intel = Column(JSON, nullable=False, default=list)
    recommended_actions = Column(JSON, nullable=False, default=list)
    affected_hosts = Column(JSON, nullable=False, default=list)
    affected_users = Column(JSON, nullable=False, default=list)
    report = Column(Text, nullable=False, default="")

    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    closed_at = Column(DateTime(timezone=True), nullable=True)

    events = relationship("Event", back_populates="incident", order_by="Event.timestamp")
    comments = relationship("IncidentComment", back_populates="incident", order_by="IncidentComment.created_at")
    assignee = relationship("User")

    def to_summary_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "confidence": self.confidence,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "status": self.status,
            "priority": self.priority,
            "assignee_id": self.assignee_id,
            "assignee_email": self.assignee.email if self.assignee else None,
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
            "comments": [c.to_dict() for c in self.comments],
        }


class IncidentComment(Base):
    __tablename__ = "incident_comments"

    id = Column(Integer, primary_key=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False, index=True)
    author_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    body = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    incident = relationship("Incident", back_populates="comments")
    author = relationship("User")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "author_email": self.author.email if self.author else None,
            "body": self.body,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Asset(Base):
    """A host, auto-discovered from ingested events and enriched manually."""

    __tablename__ = "assets"

    id = Column(Integer, primary_key=True)
    host = Column(String(255), index=True, nullable=False)
    first_seen = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    last_seen = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    event_count = Column(Integer, nullable=False, default=0)

    os = Column(String(100), nullable=True)
    department = Column(String(100), nullable=True)
    owner = Column(String(255), nullable=True)
    criticality = Column(String(20), nullable=False, default="medium")

    # Case-insensitive uniqueness: the same physical host is routinely logged
    # with different casing across sources (see correlation.py), and a plain
    # unique index on `host` would allow "abc" and "ABC" as two separate
    # rows. Enforced at the DB level (not just app-level dedup logic in
    # ingestion.py) so a genuine race between two concurrent first-sightings
    # can't create duplicates either.
    __table_args__ = (Index("ix_assets_host_lower", func.lower(host), unique=True),)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "host": self.host,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "event_count": self.event_count,
            "os": self.os,
            "department": self.department,
            "owner": self.owner,
            "criticality": self.criticality,
        }


class Notification(Base):
    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    message = Column(String(500), nullable=False)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=True)
    is_read = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "message": self.message,
            "incident_id": self.incident_id,
            "is_read": self.is_read,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
