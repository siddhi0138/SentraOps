import json
from datetime import datetime, timezone

from pgvector.sqlalchemy import Vector
from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.orm import relationship
from sqlalchemy.types import TypeDecorator

from app.db import Base

EMBEDDING_DIM = 384  # all-MiniLM-L6-v2's output size (see app/embeddings.py)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class EmbeddingVector(TypeDecorator):
    """Native pgvector column on Postgres (indexed ANN search via
    cosine_distance()). SQLite has no vector extension, so dev mode falls
    back to storing the vector as JSON text; app/rag.py does a brute-force
    cosine similarity scan in Python for that dialect instead - fine at
    dev/demo scale, not meant to scale on SQLite."""

    impl = Text
    cache_ok = True
    # TypeDecorator doesn't automatically forward the wrapped type's special
    # comparator methods (cosine_distance() etc. aren't standard SQL
    # operators SQLAlchemy knows generically) - has to be wired explicitly,
    # or Embedding.vector.cosine_distance(...) raises AttributeError. Only
    # matters on Postgres; SQLite never calls it (see app/rag.py).
    comparator_factory = Vector.comparator_factory

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(Vector(EMBEDDING_DIM))
        return dialect.type_descriptor(Text())

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if dialect.name == "postgresql":
            return value
        return json.dumps(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if dialect.name == "postgresql":
            return list(value)
        return json.loads(value)


class Organization(Base):
    """A tenant. Every user belongs to exactly one organization, and every
    piece of security data (events/incidents/assets/agent runs/...) is
    scoped to one - the whole multi-tenancy model is "one org per
    customer," not shared workspaces. `slug` is the human-typeable join
    code a new teammate uses at registration instead of an invite link."""

    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, index=True, nullable=False)
    plan = Column(String(20), nullable=False, default="free")
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    # Generated lazily on first request for the Jira webhook URL (see
    # GET /connectors/jira/webhook-url) - embedded in that URL's path so
    # Jira's own webhook call authenticates itself just by knowing the URL,
    # the same pattern Slack/Discord incoming webhooks use. Never returned
    # from to_dict() - only the dedicated endpoint that generates it exposes it.
    jira_webhook_secret = Column(String(64), nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "slug": self.slug,
            "plan": self.plan,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="auditor")
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    organization = relationship("Organization")


class RawLog(Base):
    """The untouched log payload exactly as it was ingested, for audit/replay."""

    __tablename__ = "raw_logs"

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    source_type = Column(String(50), index=True, nullable=False)
    payload = Column(Text, nullable=False)
    received_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    events = relationship("Event", back_populates="raw_log")


class Event(Base):
    """Unified event schema every log source is normalized into."""

    __tablename__ = "events"

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
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
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
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
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    host = Column(String(255), index=True, nullable=False)
    first_seen = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    last_seen = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    event_count = Column(Integer, nullable=False, default=0)

    os = Column(String(100), nullable=True)
    department = Column(String(100), nullable=True)
    owner = Column(String(255), nullable=True)
    criticality = Column(String(20), nullable=False, default="medium")

    # Case-insensitive uniqueness *per organization*: the same physical host
    # is routinely logged with different casing across sources (see
    # correlation.py), and a plain unique index on `host` would allow "abc"
    # and "ABC" as two separate rows. Enforced at the DB level (not just
    # app-level dedup logic in ingestion.py) so a genuine race between two
    # concurrent first-sightings can't create duplicates either. Scoped by
    # organization_id so two different customers can each have their own
    # "DC01" without colliding.
    __table_args__ = (Index("ix_assets_org_host_lower", organization_id, func.lower(host), unique=True),)

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


class AgentRun(Base):
    """One execution of the Milestone 3 multi-agent coordinator graph
    against an incident - the durable record behind "Decision History" and
    the "Incident Workspace" view, since the graph invocation itself is
    in-memory and would otherwise vanish once the request returns."""

    __tablename__ = "agent_runs"

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False, index=True)
    triggered_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    status = Column(String(20), nullable=False, default="running", index=True)  # running | completed | failed
    error = Column(Text, nullable=True)
    # The final AgentState dict (detection/investigation/threat_intel_findings/
    # risk/response/report/stage) minus "messages", which is stored as its
    # own AgentMessage rows instead so the conversation log is queryable.
    result = Column(JSON, nullable=True)
    started_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    incident = relationship("Incident")
    triggered_by = relationship("User")
    messages = relationship("AgentMessage", back_populates="run", order_by="AgentMessage.created_at")

    def to_summary_dict(self) -> dict:
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "status": self.status,
            "triggered_by_email": self.triggered_by.email if self.triggered_by else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "stage": (self.result or {}).get("stage"),
        }

    def to_detail_dict(self) -> dict:
        return {
            **self.to_summary_dict(),
            "error": self.error,
            "result": self.result,
            "messages": [m.to_dict() for m in self.messages],
        }


class AgentMessage(Base):
    """One entry in the inter-agent conversation log for a run - what
    "Agent Conversations" renders."""

    __tablename__ = "agent_messages"

    id = Column(Integer, primary_key=True)
    run_id = Column(Integer, ForeignKey("agent_runs.id"), nullable=False, index=True)
    agent = Column(String(30), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    run = relationship("AgentRun", back_populates="messages")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "run_id": self.run_id,
            "agent": self.agent,
            "content": self.content,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ProposedAction(Base):
    """A containment/eradication/recovery action the Response Agent
    proposed for an incident. Nothing here is ever executed automatically -
    this table exists purely to make the human-in-the-loop approval step
    durable across requests (AI recommends -> human approves -> a future
    integration executes)."""

    __tablename__ = "proposed_actions"

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False, index=True)
    agent_run_id = Column(Integer, ForeignKey("agent_runs.id"), nullable=True, index=True)
    category = Column(String(20), nullable=False, default="containment")
    description = Column(Text, nullable=False)
    status = Column(String(20), nullable=False, default="pending", index=True)
    reviewed_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    reviewed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    # Set once a human-approved action is actually dispatched to a
    # ResponseActionInstance (see app/plugins/) - status becomes "executed"
    # or "execution_failed" at that point. Still never automatic: this only
    # ever fires from a human hitting the execute endpoint after approval.
    executed_at = Column(DateTime(timezone=True), nullable=True)
    execution_result = Column(Text, nullable=True)  # JSON list of {integration, ok, message}

    incident = relationship("Incident")
    reviewed_by = relationship("User")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "agent_run_id": self.agent_run_id,
            "category": self.category,
            "description": self.description,
            "status": self.status,
            "reviewed_by_email": self.reviewed_by.email if self.reviewed_by else None,
            "reviewed_at": self.reviewed_at.isoformat() if self.reviewed_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "executed_at": self.executed_at.isoformat() if self.executed_at else None,
            "execution_result": json.loads(self.execution_result) if self.execution_result else None,
        }


class Embedding(Base):
    """A vector-searchable chunk of text plus a pointer back to what it came
    from. `content_type` + `content_id` is a loose reference (not a real FK)
    since it points at different tables depending on the type - kept generic
    so knowledge-base articles, MITRE entries, etc. can reuse this table
    later without a schema change."""

    __tablename__ = "embeddings"

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    content_type = Column(String(50), nullable=False, index=True)  # "event" | "incident" | "knowledge_chunk"
    content_id = Column(Integer, nullable=True, index=True)
    text = Column(Text, nullable=False)
    vector = Column(EmbeddingVector, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)


class KnowledgeDocument(Base):
    """Metadata for one uploaded Knowledge Base document. The actual
    searchable text lives as one or more Embedding rows (content_type=
    "knowledge_chunk", content_id=this row's id) - this table exists only
    so the KB page has something to list/delete without re-deriving a
    document's chunks from scratch each time."""

    __tablename__ = "knowledge_documents"

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    filename = Column(String(255), nullable=True)
    source = Column(String(20), nullable=False, default="upload")  # "upload" | "seed"
    chunk_count = Column(Integer, nullable=False, default=0)
    uploaded_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "filename": self.filename,
            "source": self.source,
            "chunk_count": self.chunk_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ConnectorInstance(Base):
    """An org's configured instance of a connector plugin
    (app/plugins/connectors/) - the plugin class is shared code across all
    tenants; this row is one tenant's specific config of it (e.g. which
    GitHub repo to watch) plus sync bookkeeping."""

    __tablename__ = "connector_instances"

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    plugin_key = Column(String(50), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    config = Column(JSON, nullable=False, default=dict)
    enabled = Column(Boolean, nullable=False, default=True)
    last_sync_at = Column(DateTime(timezone=True), nullable=True)
    last_sync_status = Column(String(20), nullable=True)  # "success" | "error"
    last_sync_message = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "plugin_key": self.plugin_key,
            "name": self.name,
            "config": self.config,
            "enabled": self.enabled,
            "last_sync_at": self.last_sync_at.isoformat() if self.last_sync_at else None,
            "last_sync_status": self.last_sync_status,
            "last_sync_message": self.last_sync_message,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class PlaybookTemplate(Base):
    """A catalog entry for an installable AI customization - a reusable
    prompt-template addition that changes how the platform explains an
    incident once an org "installs" it (see app/marketplace.py). This is
    deliberately NOT a new agent or a new plugin type (M4.2's plugin
    architecture explicitly kept the 6-agent LangGraph pipeline fixed) -
    installing a playbook only ever adds guidance text to an existing,
    already-audited prompt, never new code execution. A seeded, curated
    catalog, not organization-scoped - same pattern as ThreatIndicator and
    ComplianceControl."""

    __tablename__ = "playbook_templates"

    id = Column(Integer, primary_key=True)
    key = Column(String(50), nullable=False, unique=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    category = Column(String(50), nullable=False, index=True)  # "threat-type" | "compliance" | "reporting-style"
    prompt_addition = Column(Text, nullable=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "key": self.key,
            "name": self.name,
            "description": self.description,
            "category": self.category,
        }


class OrgPlaybookInstall(Base):
    """One organization's decision to enable a catalog playbook - the
    "marketplace install" record. `UniqueConstraint` makes installing the
    same playbook twice a harmless no-op at the DB level, not just an
    application-level check."""

    __tablename__ = "org_playbook_installs"

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    playbook_id = Column(Integer, ForeignKey("playbook_templates.id"), nullable=False, index=True)
    installed_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    playbook = relationship("PlaybookTemplate")

    __table_args__ = (Index("ix_org_playbook_installs_org_playbook", "organization_id", "playbook_id", unique=True),)


class ThreatIndicator(Base):
    """A known-bad indicator (IP/domain/URL/hash) the platform can match
    ingested events against. Deliberately **not** organization-scoped,
    unlike every other table in this app - threat intelligence is shared
    enrichment knowledge, not tenant data, the same way a commercial TI
    vendor's feed is one subscription shared by every customer, not a
    per-customer copy. Populated by a data migration seed (one curated
    demo indicator, so the built-in phishing_ransomware simulate scenario
    keeps demonstrating a real match out of the box) and by real live
    feeds via app/threat_intel_hub.py (e.g. URLhaus)."""

    __tablename__ = "threat_indicators"

    id = Column(Integer, primary_key=True)
    indicator = Column(String(512), nullable=False, index=True)
    indicator_type = Column(String(20), nullable=False)  # ip | domain | url | hash
    verdict = Column(String(255), nullable=False)
    confidence = Column(Integer, nullable=False, default=50)
    source = Column(String(100), nullable=False)
    tags = Column(String(255), nullable=True)
    first_seen = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    last_seen = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    __table_args__ = (Index("ix_threat_indicators_indicator_lower", func.lower(indicator), unique=True),)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "indicator": self.indicator,
            "indicator_type": self.indicator_type,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "source": self.source,
            "tags": self.tags,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }


class ApiKey(Base):
    """A machine-to-machine credential, alternative to a JWT login for
    programmatic/service access (CI pipelines, external integrations
    calling this API directly). Deliberately tied to a real `User` row
    (acts with that user's role) rather than inventing a synthetic
    principal type - every existing endpoint's `user.id`/`user.role`/
    `user.organization_id` usage keeps working unchanged, see
    app/auth.py's get_current_user(). Only `key_hash` is ever stored -
    the real key is shown once at creation and is not recoverable."""

    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String(255), nullable=False)
    key_hash = Column(String(64), nullable=False, unique=True, index=True)
    key_prefix = Column(String(20), nullable=False)  # shown in the UI so an admin can identify which key is which
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)

    user = relationship("User", foreign_keys=[user_id])
    created_by = relationship("User", foreign_keys=[created_by_id])

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "key_prefix": self.key_prefix,
            "acts_as_email": self.user.email if self.user else None,
            "created_by_email": self.created_by.email if self.created_by else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "revoked": self.revoked_at is not None,
        }


class AuditLogEntry(Base):
    """A durable record of sensitive administrative actions (role changes,
    org rename/invite-code rotation, API key create/revoke) - deliberately
    scoped to those specific actions rather than every request in the app,
    to keep the instrumentation's blast radius contained. `actor_email` is
    denormalized (not just a user_id FK) so the log entry stays readable
    even if that user is later removed."""

    __tablename__ = "audit_log_entries"

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    actor_email = Column(String(255), nullable=True)
    action = Column(String(100), nullable=False)
    details = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "actor_email": self.actor_email,
            "action": self.action,
            "details": self.details,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ShiftNote(Base):
    """A team-wide handoff note (not tied to one incident, unlike
    IncidentComment) - what the SOC Command Center's shift log renders,
    for context that doesn't belong to any single incident (e.g. "quiet
    shift, nothing to flag" or "watch host X, still investigating")."""

    __tablename__ = "shift_notes"

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    author_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    body = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    author = relationship("User")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "author_email": self.author.email if self.author else None,
            "body": self.body,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AnalystFeedback(Base):
    """A human's judgment on how accurate one AI investigation/incident
    was - the input side of the "Learning Loop": no model retraining
    happens here (out of scope, no training infra/budget), but real
    analyst corrections (false positives, missed detections, with notes)
    are fed back into future Detection Agent runs as institutional memory
    (see app/learning.py + agents/memory.py), genuinely closing the loop
    without pretending to do online ML training."""

    __tablename__ = "analyst_feedback"

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False, index=True)
    agent_run_id = Column(Integer, ForeignKey("agent_runs.id"), nullable=True, index=True)
    rating = Column(String(20), nullable=False)  # "accurate" | "false_positive" | "missed_detection"
    note = Column(Text, nullable=True)
    reviewed_by_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    incident = relationship("Incident")
    reviewed_by = relationship("User")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "agent_run_id": self.agent_run_id,
            "rating": self.rating,
            "note": self.note,
            "reviewed_by_email": self.reviewed_by.email if self.reviewed_by else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ComplianceControl(Base):
    """One entry in a fixed, seeded catalog of compliance controls (a
    curriculum, not a customer's data) - like ThreatIndicator, deliberately
    not organization-scoped. Its *status* against one organization's real
    data is computed on demand by app/compliance.py's check registry
    (keyed by `check_key`) and never cached here, so a control can never
    report a stale pass/fail."""

    __tablename__ = "compliance_controls"

    id = Column(Integer, primary_key=True)
    framework = Column(String(50), nullable=False, index=True)  # "SOC2" | "ISO27001" | "GDPR"
    control_id = Column(String(20), nullable=False)  # e.g. "CC6.1"
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    check_key = Column(String(50), nullable=False, unique=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "framework": self.framework,
            "control_id": self.control_id,
            "title": self.title,
            "description": self.description,
            "check_key": self.check_key,
        }


class ResponseActionInstance(Base):
    """An org's configured instance of a response-action plugin
    (app/plugins/actions/) - e.g. "post to our SOC Slack channel" - that
    POST /proposed-actions/{id}/execute dispatches approved actions to."""

    __tablename__ = "response_action_instances"

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    plugin_key = Column(String(50), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    config = Column(JSON, nullable=False, default=dict)
    enabled = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "plugin_key": self.plugin_key,
            "name": self.name,
            "config": self.config,
            "enabled": self.enabled,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
