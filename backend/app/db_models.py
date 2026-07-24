from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.db import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


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
        }
