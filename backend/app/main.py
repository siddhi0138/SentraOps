import csv
import io
import json
import os
import re
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Literal
from urllib.parse import parse_qs

import httpx
import redis.asyncio as aioredis
from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, Response, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from neo4j.exceptions import Neo4jError, ServiceUnavailable
from prometheus_fastapi_instrumentator import Instrumentator
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.auth import (
    Role,
    OrganizationCreate,
    RefreshRequest,
    RoleUpdate,
    TokenPair,
    UserCreate,
    UserLogin,
    UserOut,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_current_user,
    hash_password,
    require_roles,
    verify_password,
)
from app.correlation import run_correlation
from app.db import get_db, init_db
from app.db_models import (
    Asset,
    AgentRun,
    AgentMessage,
    ApiKey,
    AuditLogEntry,
    ConnectorInstance,
    Event,
    Incident,
    IncidentComment,
    KnowledgeDocument,
    Notification,
    Organization,
    PlaybookTemplate,
    ProposedAction,
    ResponseActionInstance,
    ShiftNote,
    User,
)
from app.organizations import rotate_invite_code, unique_slug
from app.agents.coordinator import run_investigation
from app.agents.runner import gather_investigation_inputs, mark_run_failed, persist_investigation_result
from app.agents.memory import build_memory_context
from app.ai import ChatConfigError, ChatProviderError, answer_question, explain_event, explain_incident, translate_query
from app.confidence import compute_dual_evidence_confidence
from app.graph import get_entity_blast_radius, get_full_graph, get_incident_subgraph, resync_graph
from app.slack_bot import (
    handle_investigate_button,
    handle_review_action_button,
    handle_slash_command,
    notify_assignment,
    notify_comment,
    notify_compliance_report,
    notify_status_change,
    provision_default_channels,
    send_report_to_slack,
)
from app.slack_oauth import (
    FRONTEND_URL,
    build_authorize_url,
    exchange_code_for_token,
    sign_oauth_state,
    verify_oauth_state,
    verify_slack_signature,
)
from app.ingestion import ingest
from app.knowledge_base import delete_document as delete_knowledge_document
from app.knowledge_base import ingest_document as ingest_knowledge_document
from app.knowledge_base import seed_sample_documents
from app.plugins import registry as plugin_registry
from app.progress import REDIS_URL, channel_name
from app.rag import search as rag_search
from app.rate_limit import limiter
from app.simulate import get_scenario
from app import bas
from app.admin import generate_api_key, record_audit
from app.command_center import get_queue as get_command_center_queue
from app.compliance import evaluate_controls, generate_report as generate_compliance_report
from app.executive import generate_briefing, get_summary as get_executive_summary
from app.learning import get_evaluation_summary, get_feedback_stats, list_feedback_for_incident, record_feedback
from app.predictive import generate_predictive_briefing, get_predictive_summary
from app.digital_twin import generate_twin_narrative, simulate_compromise
from app.observability import get_ai_observability_summary
from app.marketplace import (
    get_installed_prompt_addition,
    install_playbook,
    list_installed as list_installed_playbooks,
    list_playbooks,
    uninstall_playbook,
)
from app.streaming import publish_raw_log, stream_status
from app.tasks import consume_ingest_stream_task, investigate_incident_task
from app.threat_intel_hub import get_indicator_graph, resync_indicator_graph
from app.threat_intel_hub import search as search_indicators
from app.threat_intel_hub import sync_urlhaus


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="SentraOps", version="0.2.0", lifespan=lifespan)

# Real, Redis-backed rate limiting (see app/rate_limit.py) - applied
# selectively below to auth endpoints (brute-force protection) and
# Groq-calling AI endpoints (cost/latency protection), not blanket-applied
# to the whole API, since several frontend pages legitimately poll GET
# endpoints every few seconds (AITeamPage, SOCCommandCenterPage).
app.state.limiter = limiter


def _rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    # slowapi's own default handler returns {"error": ...} - every other
    # error response in this API uses FastAPI's {"detail": ...} shape
    # (HTTPException), which the frontend's error parsing already expects.
    response = JSONResponse({"detail": "Too many requests - please slow down and try again shortly."}, status_code=429)
    return limiter._inject_headers(response, request.state.view_rate_limit)


app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# The frontend is a separate origin (its own dev server / nginx container),
# so browser requests to this API need CORS. Comma-separated allowlist, or
# "*" (default) for local/demo use.
_cors_origins = os.environ.get("CORS_ORIGINS", "*")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if _cors_origins == "*" else [o.strip() for o in _cors_origins.split(",")],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Exposes GET /metrics (request rate/latency/status by route, out of the
# box) for Prometheus to scrape - see app/metrics.py for the
# investigation-specific metrics a generic HTTP instrumentator can't see.
Instrumentator().instrument(app).expose(app)


class IngestRequest(BaseModel):
    logs: list[Any]


def _get_scoped_or_404(db: Session, model, obj_id: int, organization_id: int, not_found: str):
    """One place for the "look up by id, but only within the caller's own
    organization" pattern that every single-resource endpoint below needs
    (Incident/Event/Asset/AgentRun/ProposedAction all have `id` +
    `organization_id`). Centralizing it means there's exactly one place to
    get the filter right, instead of ~15 hand-copied `db.get(Model, id)`
    calls silently missing the org check - a missed filter here is a real
    cross-tenant data leak, not just a bug."""
    obj = db.query(model).filter(model.id == obj_id, model.organization_id == organization_id).first()
    if obj is None:
        raise HTTPException(status_code=404, detail=not_found)
    return obj


def _user_out(user: User) -> UserOut:
    return UserOut(
        id=user.id,
        email=user.email,
        role=user.role,
        is_active=user.is_active,
        organization_id=user.organization_id,
        organization_name=user.organization.name,
        organization_slug=user.organization.slug,
    )


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/_debug/client-ip")
def _debug_client_ip(request: Request) -> dict:
    # TEMPORARY - diagnosing why per-IP rate limiting stopped accumulating
    # after switching the key func to prefer X-Forwarded-For's first hop;
    # remove this endpoint once root-caused.
    from app.rate_limit import _client_ip
    from slowapi.util import get_remote_address

    return {
        "xff": request.headers.get("x-forwarded-for") or "<none>",
        "client_host": get_remote_address(request),
        "computed_key": _client_ip(request),
    }


@app.post("/organizations", response_model=UserOut)
@limiter.limit("5/minute")
def create_organization(request: Request, payload: OrganizationCreate, db: Session = Depends(get_db)) -> UserOut:
    """Sign up a brand new company - creates the Organization and its
    first user as that org's admin, in one call. Joining an *existing*
    org is the separate /auth/register flow below, which takes an
    org slug instead of a name and defaults to viewer."""
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    org = Organization(name=payload.organization_name, slug=unique_slug(db, payload.organization_name))
    db.add(org)
    db.flush()  # need org.id before creating the user row

    user = User(
        organization_id=org.id,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role=Role.owner.value,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return _user_out(user)


@app.post("/auth/register", response_model=UserOut)
@limiter.limit("5/minute")
def register(request: Request, payload: UserCreate, db: Session = Depends(get_db)) -> UserOut:
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    org = db.query(Organization).filter(Organization.slug == payload.organization_slug).first()
    if not org:
        raise HTTPException(status_code=404, detail="Unknown organization - check the invite code")

    # New teammates default to the read-only Auditor role; an existing
    # owner/admin raises their role via PATCH /users/{id}/role. (The org's
    # very first user, created via POST /organizations instead of here, is
    # the one who starts as Owner.)
    user = User(
        organization_id=org.id,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role=Role.auditor.value,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return _user_out(user)


@app.post("/auth/login", response_model=TokenPair)
@limiter.limit("10/minute")
def login(request: Request, payload: UserLogin, db: Session = Depends(get_db)) -> TokenPair:
    user = db.query(User).filter(User.email == payload.email).first()
    if not user or not user.is_active or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    return TokenPair(access_token=create_access_token(user.id), refresh_token=create_refresh_token(user.id))


@app.post("/auth/refresh", response_model=TokenPair)
@limiter.limit("10/minute")
def refresh(request: Request, payload: RefreshRequest, db: Session = Depends(get_db)) -> TokenPair:
    user_id = decode_token(payload.refresh_token, "refresh")
    user = db.get(User, user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    return TokenPair(access_token=create_access_token(user.id), refresh_token=create_refresh_token(user.id))


@app.get("/auth/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)) -> UserOut:
    return _user_out(user)


@app.get("/users", response_model=list[UserOut])
def list_users(
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> list[UserOut]:
    # Every role can see who's on the team (harmless - just email + role);
    # only role *changes* stay Owner/Admin-only (see update_user_role
    # below). Scoped to the caller's own organization - no one ever sees or
    # manages another tenant's user list.
    users = db.query(User).filter(User.organization_id == user.organization_id).order_by(User.id).all()
    return [_user_out(u) for u in users]


@app.patch("/users/{user_id}/role", response_model=UserOut)
def update_user_role(
    user_id: int,
    payload: RoleUpdate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_roles(Role.owner, Role.admin)),
) -> UserOut:
    # organization_id filter here isn't just data hygiene - without it an
    # admin in one org could promote/demote a user in a *different* org by
    # guessing/enumerating user ids.
    user = db.query(User).filter(User.id == user_id, User.organization_id == admin.organization_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Only an Owner can grant or revoke Owner itself - otherwise any Admin
    # could silently promote themselves (or anyone else) to the org's top
    # role, which Admin alone should never be able to do.
    if (payload.role == Role.owner or user.role == Role.owner.value) and admin.role != Role.owner.value:
        raise HTTPException(status_code=403, detail="Only an Owner can grant or revoke the Owner role")

    old_role = user.role
    user.role = payload.role.value
    record_audit(
        db, admin.organization_id, admin.email, "role_changed",
        {"target_email": user.email, "old_role": old_role, "new_role": user.role},
    )
    db.commit()
    db.refresh(user)
    return _user_out(user)


class OrganizationUpdate(BaseModel):
    name: str = Field(min_length=2, max_length=255)


@app.get("/organizations/current")
def get_current_organization(
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    org = db.get(Organization, user.organization_id)
    return {"id": org.id, "name": org.name, "slug": org.slug, "plan": org.plan, "created_at": org.created_at.isoformat()}


@app.patch("/organizations/current")
def rename_current_organization(
    payload: OrganizationUpdate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_roles(Role.owner, Role.admin)),
) -> dict:
    org = db.get(Organization, admin.organization_id)
    old_name = org.name
    org.name = payload.name
    record_audit(db, admin.organization_id, admin.email, "org_renamed", {"old_name": old_name, "new_name": org.name})
    db.commit()
    db.refresh(org)
    return {"id": org.id, "name": org.name, "slug": org.slug, "plan": org.plan, "created_at": org.created_at.isoformat()}


@app.post("/organizations/current/rotate-invite-code")
def rotate_current_invite_code(
    db: Session = Depends(get_db),
    admin: User = Depends(require_roles(Role.owner, Role.admin)),
) -> dict:
    org = db.get(Organization, admin.organization_id)
    old_slug = org.slug
    org.slug = rotate_invite_code(db, org)
    record_audit(db, admin.organization_id, admin.email, "invite_code_rotated", {"old_slug": old_slug, "new_slug": org.slug})
    db.commit()
    db.refresh(org)
    return {"id": org.id, "name": org.name, "slug": org.slug, "plan": org.plan, "created_at": org.created_at.isoformat()}


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    user_id: int | None = None  # defaults to the creating admin's own identity/role


@app.post("/api-keys")
def create_api_key(
    payload: ApiKeyCreate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_roles(Role.owner, Role.admin)),
) -> dict:
    acting_user_id = payload.user_id if payload.user_id is not None else admin.id
    acting_user = _get_scoped_or_404(db, User, acting_user_id, admin.organization_id, "User not found")

    raw_key, key_hash, key_prefix = generate_api_key()
    api_key = ApiKey(
        organization_id=admin.organization_id,
        user_id=acting_user.id,
        name=payload.name,
        key_hash=key_hash,
        key_prefix=key_prefix,
        created_by_id=admin.id,
    )
    db.add(api_key)
    record_audit(db, admin.organization_id, admin.email, "api_key_created", {"name": payload.name, "acts_as": acting_user.email})
    db.commit()
    db.refresh(api_key)
    # The only time the real key is ever returned - store it now, it can't
    # be retrieved again (only its hash is kept).
    return {**api_key.to_dict(), "key": raw_key}


@app.get("/api-keys")
def list_api_keys(
    db: Session = Depends(get_db),
    admin: User = Depends(require_roles(Role.owner, Role.admin)),
) -> dict:
    keys = db.query(ApiKey).filter(ApiKey.organization_id == admin.organization_id).order_by(ApiKey.created_at.desc()).all()
    return {"api_keys": [k.to_dict() for k in keys]}


@app.post("/api-keys/{key_id}/revoke")
def revoke_api_key(
    key_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_roles(Role.owner, Role.admin)),
) -> dict:
    api_key = _get_scoped_or_404(db, ApiKey, key_id, admin.organization_id, "API key not found")
    if api_key.revoked_at is None:
        api_key.revoked_at = datetime.now(timezone.utc)
        record_audit(db, admin.organization_id, admin.email, "api_key_revoked", {"name": api_key.name})
        db.commit()
        db.refresh(api_key)
    return api_key.to_dict()


@app.get("/audit-log")
def list_audit_log(
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    admin: User = Depends(require_roles(Role.owner, Role.admin)),
) -> dict:
    entries = (
        db.query(AuditLogEntry)
        .filter(AuditLogEntry.organization_id == admin.organization_id)
        .order_by(AuditLogEntry.created_at.desc())
        .limit(limit)
        .all()
    )
    return {"entries": [e.to_dict() for e in entries]}


@app.post("/ingest/upload")
@limiter.limit("20/minute")
async def ingest_upload(
    request: Request,
    source_type: str = Query(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst)),
) -> dict:
    # Must be registered before /ingest/{source_type} below - otherwise that
    # route's path-shape matches "/ingest/upload" first (source_type="upload")
    # and this endpoint is silently unreachable.
    raw_bytes = await file.read()
    try:
        content = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be UTF-8 encoded")

    if file.filename and file.filename.lower().endswith(".csv"):
        raw_items: list[Any] = list(csv.DictReader(io.StringIO(content)))
    else:
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid JSON: {exc}")
        raw_items = parsed if isinstance(parsed, list) else [parsed]

    try:
        events, skipped = ingest(db, user.organization_id, source_type, raw_items)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return {"ingested": len(events), "skipped": skipped}


@app.get("/knowledge-base")
def list_knowledge_documents(
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    documents = (
        db.query(KnowledgeDocument)
        .filter(KnowledgeDocument.organization_id == user.organization_id)
        .order_by(KnowledgeDocument.created_at.desc())
        .all()
    )
    return {"documents": [d.to_dict() for d in documents]}


@app.post("/knowledge-base/upload")
async def upload_knowledge_document(
    title: str | None = Query(None),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst)),
) -> dict:
    """Accepts plain text/Markdown only for now - no PDF parsing dependency
    yet. Chunked, embedded with the same local model as events/incidents,
    and picked up automatically by /chat and /search since those already
    query across all content_types unless one is explicitly requested."""
    raw_bytes = await file.read()
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be UTF-8 encoded plain text or Markdown")

    if not text.strip():
        raise HTTPException(status_code=400, detail="File is empty")

    document = ingest_knowledge_document(
        db, user.organization_id,
        title=title or file.filename or "Untitled document",
        text=text, filename=file.filename, source="upload", uploaded_by_user_id=user.id,
    )
    return document.to_dict()


@app.post("/knowledge-base/seed-samples")
def seed_knowledge_base_samples(
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst)),
) -> dict:
    created = seed_sample_documents(db, user.organization_id)
    return {"created": [d.to_dict() for d in created]}


@app.delete("/knowledge-base/{document_id}")
def delete_knowledge_base_document(
    document_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst)),
) -> dict:
    deleted = delete_knowledge_document(db, user.organization_id, document_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Document not found")
    return {"deleted": True}


@app.post("/ingest/{source_type}")
@limiter.limit("20/minute")
def ingest_logs(
    request: Request,
    source_type: str,
    payload: IngestRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst)),
) -> dict:
    try:
        events, skipped = ingest(db, user.organization_id, source_type, payload.logs)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return {"ingested": len(events), "skipped": skipped, "events": [e.to_dict() for e in events]}


@app.post("/ingest/{source_type}/stream")
@limiter.limit("20/minute")
def ingest_logs_streaming(
    request: Request,
    source_type: str,
    payload: IngestRequest,
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst)),
) -> dict:
    """Queues raw logs onto this org's Redis Stream and returns
    immediately, instead of parsing/persisting them inline on this request
    like POST /ingest/{source_type} above - Redis Streams + a dispatched
    Celery consumer standing in for a Kafka+Spark-Streaming pipeline (see
    app/streaming.py). Meant for higher-volume/live sources where a
    producer shouldn't block on ingestion; POST /ingest/{source_type}
    and the connector /sync endpoint stay synchronous since their
    immediate ingested-count response is valuable for a "test now" UX."""
    for item in payload.logs:
        publish_raw_log(user.organization_id, source_type, item)
    consume_ingest_stream_task.delay(user.organization_id)
    return {"queued": len(payload.logs)}


@app.get("/streaming/status")
def get_streaming_status(user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive))) -> dict:
    return stream_status(user.organization_id)


@app.post("/simulate/{scenario}")
@limiter.limit("5/minute")
def simulate(
    request: Request,
    scenario: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst)),
) -> dict:
    """Real-with-fallback, the same provider pattern as VirusTotal/AbuseIPDB
    (app/threat_intel_providers.py): tries a real BAS campaign (app/bas.py)
    against a real Kubernetes pod first, and only falls back to the canned
    synthetic scenario when no cluster is available or the live run fails
    for any reason - never silently presents synthetic data as real, the
    response's "mode" field always says honestly which one happened."""
    try:
        logs_by_source = get_scenario(scenario)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    try:
        bas_events = bas.run_campaign(user.organization_id, bas.pick_random_campaign())
        events, skipped = ingest(db, user.organization_id, "bas", bas_events)
        return {"scenario": scenario, "mode": "real", "sources": {"bas": {"ingested": len(events), "skipped": skipped}}}
    except Exception:
        pass  # no cluster access, or a live run failed - fall back below

    results = {}
    for source_type, raw_items in logs_by_source.items():
        events, skipped = ingest(db, user.organization_id, source_type, raw_items)
        results[source_type] = {"ingested": len(events), "skipped": skipped}

    return {"scenario": scenario, "mode": "synthetic", "sources": results}


@app.get("/bas/techniques")
def list_bas_techniques(user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst))) -> dict:
    return {
        "techniques": [
            {"id": tid, "name": t["name"], "category": t["category"], "severity": t["severity"]}
            for tid, t in bas.TECHNIQUES.items()
        ]
    }


class BasRunRequest(BaseModel):
    technique_ids: list[str] = Field(default_factory=lambda: list(bas.TECHNIQUES))


@app.post("/bas/run")
@limiter.limit("5/minute")
def run_bas_campaign(
    request: Request,
    payload: BasRunRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst)),
) -> dict:
    """Executes real MITRE ATT&CK techniques (app/bas.py) inside a real,
    sandboxed Kubernetes pod - genuine attacker behavior against a real
    (if disposable) target, not synthetic canned data like /simulate. The
    resulting real command output is ingested through the same pipeline
    as every other log source, so it flows into real correlation/AI
    investigation like anything else."""
    unknown = [tid for tid in payload.technique_ids if tid not in bas.TECHNIQUES]
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown technique id(s): {unknown}")

    try:
        raw_items = bas.run_campaign(user.organization_id, payload.technique_ids)
    except bas.BasNotConfiguredError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        # A real cluster is a real system boundary (pod scheduling failure,
        # image pull error, RBAC misconfiguration, ...) - surface it as a
        # diagnosable 502, not a bare unhandled 500 an analyst can't act on.
        raise HTTPException(status_code=502, detail=f"BAS run failed: {exc}")

    events, skipped = ingest(db, user.organization_id, "bas", raw_items)
    return {"ran": len(payload.technique_ids), "ingested": len(events), "skipped": skipped}


@app.delete("/bas/target")
def teardown_bas_target(
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst)),
) -> dict:
    try:
        deleted = bas.teardown_target_pod(user.organization_id)
    except bas.BasNotConfiguredError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    return {"deleted": deleted}


def _csv_row(row: dict) -> dict:
    # OWASP CSV injection: a cell starting with =/+/-/@ is executed as a
    # formula by Excel/Sheets when opened. Log fields (message, host, title,
    # ...) can contain attacker-controlled text, so neutralize before export.
    return {
        key: ("'" + value if isinstance(value, str) and value[:1] in ("=", "+", "-", "@") else value)
        for key, value in row.items()
    }


def _filter_events(
    db: Session,
    organization_id: int,
    q: str | None,
    event_type: str | None,
    severity: str | None,
    username: str | None,
    host: str | None,
    source_ip: str | None,
):
    query = db.query(Event).filter(Event.organization_id == organization_id)

    if event_type:
        query = query.filter(Event.event_type == event_type)
    if severity:
        query = query.filter(Event.severity == severity)
    if username:
        query = query.filter(Event.username == username)
    if host:
        query = query.filter(Event.host == host)
    if source_ip:
        query = query.filter(Event.source_ip == source_ip)
    if q:
        like = f"%{q}%"
        query = query.filter(or_(
            Event.username.ilike(like),
            Event.host.ilike(like),
            Event.source_ip.ilike(like),
            Event.message.ilike(like),
            Event.event_type.ilike(like),
        ))

    return query


@app.get("/events")
def list_events(
    q: str | None = None,
    event_type: str | None = None,
    severity: str | None = None,
    username: str | None = None,
    host: str | None = None,
    source_ip: str | None = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    query = _filter_events(db, user.organization_id, q, event_type, severity, username, host, source_ip)
    total = query.count()
    events = query.order_by(Event.timestamp.desc()).offset(offset).limit(min(limit, 500)).all()

    return {"total": total, "events": [e.to_dict() for e in events]}


@app.get("/events/export.csv")
def export_events_csv(
    q: str | None = None,
    event_type: str | None = None,
    severity: str | None = None,
    username: str | None = None,
    host: str | None = None,
    source_ip: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> Response:
    events = (
        _filter_events(db, user.organization_id, q, event_type, severity, username, host, source_ip)
        .order_by(Event.timestamp.desc())
        .limit(5000)
        .all()
    )

    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=["id", "timestamp", "host", "username", "source_ip", "event_type", "severity", "message", "source_type", "incident_id"])
    writer.writeheader()
    for event in events:
        writer.writerow(_csv_row(event.to_dict()))

    return Response(
        content=buffer.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=events.csv"},
    )


@app.get("/events/{event_id}/explain")
@limiter.limit("30/minute")
def explain_event_endpoint(
    request: Request,
    event_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    """AI-generated plain-language explanation of a single raw event - one
    Groq call, not persisted (regenerated on request)."""
    event = db.query(Event).filter(Event.id == event_id, Event.organization_id == user.organization_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    event_text = (
        f"timestamp: {event.timestamp.isoformat() if event.timestamp else 'unknown'}\n"
        f"host: {event.host}\n"
        f"username: {event.username or 'unknown'}\n"
        f"source_ip: {event.source_ip or 'unknown'}\n"
        f"event_type: {event.event_type}\n"
        f"severity: {event.severity}\n"
        f"source_type: {event.source_type}\n"
        f"message: {event.message}"
    )
    try:
        return explain_event(event_text)
    except ChatConfigError:
        raise HTTPException(status_code=503, detail="AI chat isn't configured - set GROQ_API_KEY")
    except ChatProviderError as exc:
        raise HTTPException(status_code=502, detail=f"AI provider error: {exc}")


@app.post("/correlate")
def correlate(
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst)),
) -> dict:
    incidents = run_correlation(db, user.organization_id)
    return {"incidents_created": len(incidents), "incidents": [i.to_summary_dict() for i in incidents]}


@app.get("/incidents")
def list_incidents(
    status: str | None = None,
    risk_level: str | None = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    query = db.query(Incident).filter(Incident.organization_id == user.organization_id)
    if status:
        query = query.filter(Incident.status == status)
    if risk_level:
        query = query.filter(Incident.risk_level == risk_level)

    total = query.count()
    incidents = query.order_by(Incident.created_at.desc()).offset(offset).limit(min(limit, 500)).all()

    return {"total": total, "incidents": [i.to_summary_dict() for i in incidents]}


@app.get("/incidents/export.csv")
def export_incidents_csv(
    status: str | None = None,
    risk_level: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> Response:
    query = db.query(Incident).filter(Incident.organization_id == user.organization_id)
    if status:
        query = query.filter(Incident.status == status)
    if risk_level:
        query = query.filter(Incident.risk_level == risk_level)
    incidents = query.order_by(Incident.created_at.desc()).limit(5000).all()

    fieldnames = ["id", "title", "confidence", "risk_score", "risk_level", "status", "priority", "assignee_email", "event_count", "created_at"]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for incident in incidents:
        writer.writerow(_csv_row(incident.to_summary_dict()))

    return Response(
        content=buffer.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=incidents.csv"},
    )


@app.get("/incidents/{incident_id}")
def get_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    incident = _get_scoped_or_404(db, Incident, incident_id, user.organization_id, "Incident not found")
    return incident.to_detail_dict()


@app.get("/incidents/{incident_id}/report.md")
def download_incident_report(
    incident_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> Response:
    incident = _get_scoped_or_404(db, Incident, incident_id, user.organization_id, "Incident not found")

    return Response(
        content=incident.report,
        media_type="text/markdown",
        headers={"Content-Disposition": f"attachment; filename=incident-{incident_id}-report.md"},
    )


@app.post("/incidents/{incident_id}/report/send-to-slack")
def send_incident_report_to_slack(
    incident_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst)),
) -> dict:
    """The "also send to Slack" half of the Download Report button - a real
    file upload (see app/slack_bot.py.send_report_to_slack), not a link or
    a truncated text dump. A missing/unconfigured Slack connector is a
    normal, expected outcome here (most orgs won't have one), not an error
    worth a non-200 status - the frontend just shows whatever message comes
    back."""
    incident = _get_scoped_or_404(db, Incident, incident_id, user.organization_id, "Incident not found")
    ok, message = send_report_to_slack(db, incident)
    return {"ok": ok, "message": message}


@app.get("/incidents/{incident_id}/explain")
@limiter.limit("20/minute")
def explain_incident_endpoint(
    request: Request,
    incident_id: int,
    audience: Literal["analyst", "executive"] = "analyst",
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    """AI-generated explanation, timeline narrative, and structured summary
    for one incident - one Groq call, not persisted (regenerated on
    request), so this reflects the incident's current report every time.
    `audience=executive` swaps the tone for a non-technical reader."""
    incident = _get_scoped_or_404(db, Incident, incident_id, user.organization_id, "Incident not found")
    playbook_guidance = get_installed_prompt_addition(db, user.organization_id)

    try:
        return explain_incident(incident.report, incident.confidence, audience=audience, playbook_guidance=playbook_guidance)
    except ChatConfigError:
        raise HTTPException(status_code=503, detail="AI chat isn't configured - set GROQ_API_KEY")
    except ChatProviderError as exc:
        raise HTTPException(status_code=502, detail=f"AI provider error: {exc}")


@app.get("/incidents/{incident_id}/similar")
def similar_incidents(
    incident_id: int,
    k: int = 5,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    """Reuses the incident's own report as a semantic search query against
    every other incident's already-stored embedding - no Groq call, just
    the same local/free embedding model. Excludes itself from the results
    (it's always its own closest match)."""
    incident = _get_scoped_or_404(db, Incident, incident_id, user.organization_id, "Incident not found")

    raw_results = rag_search(db, user.organization_id, incident.report, content_type="incident", k=k + 1)
    matches = []
    for result in raw_results:
        if result["content_id"] == incident_id or len(matches) >= k:
            continue
        other = db.get(Incident, result["content_id"])
        if other:
            matches.append({**other.to_summary_dict(), "similarity": result["score"]})

    return {"incident_id": incident_id, "matches": matches}


@app.get("/incidents/{incident_id}/memory")
def incident_memory(
    incident_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    """The same cross-incident institutional memory the AI Security Team
    reads from before investigating - similar past incidents and repeat
    hosts/users - exposed standalone so an analyst can see what the team
    already knows going in, before spending a Groq call on an investigation.
    No LLM call, same free/local embedding search `similar` uses."""
    incident = _get_scoped_or_404(db, Incident, incident_id, user.organization_id, "Incident not found")

    return {"incident_id": incident_id, **build_memory_context(db, incident)}


class FeedbackCreate(BaseModel):
    rating: Literal["accurate", "false_positive", "missed_detection"]
    note: str | None = None
    agent_run_id: int | None = None


@app.post("/incidents/{incident_id}/feedback")
def create_incident_feedback(
    incident_id: int,
    payload: FeedbackCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst)),
) -> dict:
    """The Learning Loop's input: a human judgment on how accurate this
    incident's AI investigation was. No model retraining happens here -
    real corrections (false positives / missed detections, with a note)
    are fed into future Detection Agent runs as institutional memory (see
    agents/memory.py) instead."""
    incident = _get_scoped_or_404(db, Incident, incident_id, user.organization_id, "Incident not found")
    feedback = record_feedback(
        db,
        organization_id=user.organization_id,
        incident_id=incident.id,
        rating=payload.rating,
        note=payload.note,
        reviewed_by_id=user.id,
        agent_run_id=payload.agent_run_id,
    )
    return feedback.to_dict()


@app.get("/incidents/{incident_id}/feedback")
def list_incident_feedback(
    incident_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    incident = _get_scoped_or_404(db, Incident, incident_id, user.organization_id, "Incident not found")
    feedback = list_feedback_for_incident(db, incident.id)
    return {"incident_id": incident_id, "feedback": [f.to_dict() for f in feedback]}


@app.get("/learning/stats")
def learning_stats(
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    return get_feedback_stats(db, user.organization_id)


@app.get("/learning/evaluation")
def learning_evaluation(
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    """Cross-references real investigation timing/confidence, real analyst
    accuracy ratings, and real human approve/reject decisions - see
    app/learning.py's get_evaluation_summary docstring for what this
    deliberately does NOT claim (no fabricated per-agent accuracy)."""
    return get_evaluation_summary(db, user.organization_id)


@app.post("/incidents/{incident_id}/investigate")
@limiter.limit("5/minute")
def investigate_incident(
    request: Request,
    incident_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst)),
) -> dict:
    """Milestone 3: runs the autonomous multi-agent pipeline (Detection ->
    Investigation -> Threat Intel -> Risk -> Response -> Report) against this
    incident's already-correlated timeline via the LangGraph coordinator.
    Blocks until the full ~8-10s chain finishes and returns the complete
    result in one response - kept around (alongside the async
    /investigate-live) for callers that just want the final answer without
    subscribing to a WebSocket. Persists an AgentRun (+ its AgentMessage
    log) either way, so a failed run is still visible in the incident's
    Decision History, not silently lost."""
    incident = _get_scoped_or_404(db, Incident, incident_id, user.organization_id, "Incident not found")

    run = AgentRun(organization_id=user.organization_id, incident_id=incident_id, triggered_by_id=user.id, status="running")
    db.add(run)
    db.commit()
    db.refresh(run)

    timeline, asset_dicts, memory, graph_context = gather_investigation_inputs(db, incident)

    try:
        state = run_investigation(incident, timeline, asset_dicts, memory, graph_context)
    except ChatConfigError:
        mark_run_failed(db, run, "GROQ_API_KEY is not set")
        raise HTTPException(status_code=503, detail="AI chat isn't configured - set GROQ_API_KEY")
    except ChatProviderError as exc:
        mark_run_failed(db, run, str(exc))
        raise HTTPException(status_code=502, detail=f"AI provider error: {exc}")

    persisted_actions = persist_investigation_result(db, run, incident_id, state)

    state["run_id"] = run.id
    state["response"]["proposed_actions"] = [a.to_dict() for a in persisted_actions]
    return state


@app.post("/incidents/{incident_id}/investigate-live")
@limiter.limit("10/minute")
def investigate_incident_live(
    request: Request,
    incident_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst)),
) -> dict:
    """Same investigation as /investigate, but dispatches the chain to a
    Celery worker and returns immediately with a run id instead of
    blocking the request for the whole ~8-10s chain. The frontend opens
    GET /ws/agent-runs/{run_id} right after this call to watch each agent
    complete in real time - that's the "AI Team" live status view."""
    incident = _get_scoped_or_404(db, Incident, incident_id, user.organization_id, "Incident not found")

    run = AgentRun(organization_id=user.organization_id, incident_id=incident_id, triggered_by_id=user.id, status="running")
    db.add(run)
    db.commit()
    db.refresh(run)

    investigate_incident_task.delay(run.id, incident_id)

    return {"run_id": run.id, "incident_id": incident_id, "status": run.status}


@app.websocket("/ws/agent-runs/{run_id}")
async def agent_run_progress_ws(websocket: WebSocket, run_id: int, db: Session = Depends(get_db)) -> None:
    """Streams per-agent progress for one investigate-live run over Redis
    pub/sub as the Celery task (app/tasks.py) works through the chain.
    Auth is a `?token=` query param, not an Authorization header - browsers'
    native WebSocket API can't set custom headers on the handshake."""
    await websocket.accept()

    token = websocket.query_params.get("token")
    if not token:
        await websocket.send_json({"type": "error", "error": "Missing token"})
        await websocket.close(code=1008)
        return
    try:
        user_id = decode_token(token, "access")
    except HTTPException:
        await websocket.send_json({"type": "error", "error": "Invalid or expired token"})
        await websocket.close(code=1008)
        return

    user = db.get(User, user_id)
    if user is None or not user.is_active:
        await websocket.send_json({"type": "error", "error": "User not found or inactive"})
        await websocket.close(code=1008)
        return

    # organization_id check here matters, not just existence - without it
    # any authenticated user could subscribe to another tenant's agent run
    # just by guessing/incrementing run_id.
    run = db.query(AgentRun).filter(AgentRun.id == run_id, AgentRun.organization_id == user.organization_id).first()
    if run is None:
        await websocket.send_json({"type": "error", "error": "Agent run not found"})
        await websocket.close()
        return
    if run.status in ("completed", "failed"):
        # Already done before the client's handshake finished - Redis pub/sub
        # doesn't replay history to new subscribers, so there's no message
        # left to wait for. Report the terminal state directly instead of
        # hanging forever.
        await websocket.send_json({"type": run.status, "run_id": run_id, "error": run.error})
        await websocket.close()
        return

    redis_client = aioredis.from_url(REDIS_URL)
    pubsub = redis_client.pubsub()
    channel = channel_name(run_id)
    await pubsub.subscribe(channel)
    try:
        async for message in pubsub.listen():
            if message["type"] != "message":
                continue
            raw = message["data"]
            text = raw.decode() if isinstance(raw, bytes) else raw
            await websocket.send_text(text)
            if json.loads(text).get("type") in ("completed", "failed"):
                break
    except WebSocketDisconnect:
        pass
    finally:
        await pubsub.unsubscribe(channel)
        await pubsub.aclose()
        await redis_client.aclose()
        try:
            await websocket.close()
        except RuntimeError:
            pass


@app.get("/agent-runs")
def list_all_agent_runs(
    status: Literal["running", "completed", "failed"] | None = None,
    limit: int = Query(default=20, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    """Cross-incident feed of recent investigations - what the "AI Team" /
    Coordinator Dashboard view renders, as opposed to
    /incidents/{id}/agent-runs which is scoped to one incident."""
    query = db.query(AgentRun).filter(AgentRun.organization_id == user.organization_id).order_by(AgentRun.started_at.desc())
    if status:
        query = query.filter(AgentRun.status == status)
    runs = query.limit(limit).all()
    return {"runs": [{**r.to_summary_dict(), "incident_title": r.incident.title if r.incident else None} for r in runs]}


@app.get("/incidents/{incident_id}/agent-runs")
def list_agent_runs(
    incident_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    incident = _get_scoped_or_404(db, Incident, incident_id, user.organization_id, "Incident not found")

    runs = db.query(AgentRun).filter(AgentRun.incident_id == incident.id).order_by(AgentRun.started_at.desc()).all()
    return {"incident_id": incident_id, "runs": [r.to_summary_dict() for r in runs]}


@app.get("/agent-runs/{run_id}")
def get_agent_run(
    run_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    run = _get_scoped_or_404(db, AgentRun, run_id, user.organization_id, "Agent run not found")
    return run.to_detail_dict()


@app.get("/incidents/{incident_id}/proposed-actions")
def list_proposed_actions(
    incident_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    incident = _get_scoped_or_404(db, Incident, incident_id, user.organization_id, "Incident not found")

    actions = (
        db.query(ProposedAction)
        .filter(ProposedAction.incident_id == incident.id)
        .order_by(ProposedAction.created_at)
        .all()
    )
    return {"incident_id": incident_id, "actions": [a.to_dict() for a in actions]}


class ProposedActionReview(BaseModel):
    status: Literal["approved", "rejected"]


@app.patch("/proposed-actions/{action_id}")
def review_proposed_action(
    action_id: int,
    payload: ProposedActionReview,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst)),
) -> dict:
    """The human-in-the-loop approval gate: the Response Agent only ever
    proposes actions, and nothing anywhere in this app executes one - this
    endpoint just records a human's decision on it."""
    action = _get_scoped_or_404(db, ProposedAction, action_id, user.organization_id, "Proposed action not found")
    if action.status != "pending":
        raise HTTPException(status_code=400, detail=f"Action already {action.status}")

    action.status = payload.status
    action.reviewed_by_id = user.id
    action.reviewed_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(action)
    return action.to_dict()


@app.get("/plugins/connectors")
def list_connector_plugins(user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive))) -> dict:
    """The catalog of connector *types* available to configure (app/plugins/
    connectors/) - not an org's configured instances, see GET /connectors
    for those."""
    return {"connectors": plugin_registry.list_connectors()}


@app.get("/plugins/response-actions")
def list_response_action_plugins(user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive))) -> dict:
    return {"actions": plugin_registry.list_actions()}


class ConnectorCreate(BaseModel):
    plugin_key: str
    name: str
    config: dict = {}


@app.post("/connectors")
def create_connector(
    payload: ConnectorCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin)),
) -> dict:
    try:
        plugin_registry.get_connector(payload.plugin_key)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    instance = ConnectorInstance(
        organization_id=user.organization_id,
        plugin_key=payload.plugin_key,
        name=payload.name,
        config=payload.config,
    )
    db.add(instance)
    db.commit()
    db.refresh(instance)
    return instance.to_dict()


@app.get("/connectors")
def list_connectors(
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    instances = db.query(ConnectorInstance).filter(ConnectorInstance.organization_id == user.organization_id).all()
    return {"connectors": [c.to_dict() for c in instances]}


class ConnectorConfigUpdate(BaseModel):
    config: dict


@app.patch("/connectors/{connector_id}")
def update_connector_config(
    connector_id: int,
    payload: ConnectorConfigUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin)),
) -> dict:
    """Merges the given keys into the connector's existing config rather
    than replacing it wholesale - lets extra settings (e.g. Slack's
    critical_channel/soc_team_channel/executive_channel/compliance_channel,
    see app/slack_bot.py's _post_to_named_channel) be added after an OAuth
    install without an admin ever seeing or re-entering the
    access_token/team_id/etc. they never typed in themselves."""
    instance = _get_scoped_or_404(db, ConnectorInstance, connector_id, user.organization_id, "Connector not found")
    merged = {**(instance.config or {}), **payload.config}
    # A changed "*_channel" name invalidates its previously cached
    # "*_channel_id" - otherwise the relevant notify_* function would keep
    # posting to the *old* channel until some other trigger happened to
    # clear it.
    for key in payload.config:
        if key.endswith("_channel"):
            merged.pop(f"{key}_id", None)
    instance.config = merged
    db.commit()
    db.refresh(instance)
    return instance.to_dict()


@app.post("/connectors/{connector_id}/test")
def test_connector(
    connector_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst)),
) -> dict:
    instance = _get_scoped_or_404(db, ConnectorInstance, connector_id, user.organization_id, "Connector not found")
    plugin = plugin_registry.get_connector(instance.plugin_key)
    ok, message = plugin.test_connection(instance.config or {})
    return {"ok": ok, "message": message}


@app.post("/connectors/{connector_id}/sync")
def sync_connector(
    connector_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst)),
) -> dict:
    """Pulls from the connector's external source right now and ingests the
    result through the same app/ingestion.py.ingest() every other source
    (file upload, /ingest/{source_type}) already goes through - a connector
    is just another way to produce raw_items, not a separate pipeline."""
    instance = _get_scoped_or_404(db, ConnectorInstance, connector_id, user.organization_id, "Connector not found")
    plugin = plugin_registry.get_connector(instance.plugin_key)

    events, skipped = [], 0
    try:
        raw_items = plugin.pull(instance.config or {})
        events, skipped = ingest(db, user.organization_id, plugin.source_type, raw_items)
        instance.last_sync_status = "success"
        instance.last_sync_message = f"Ingested {len(events)} event(s), skipped {skipped}"
    except Exception as exc:
        # A third-party integration is a real system boundary - it will
        # sometimes be down/rate-limited/misconfigured, and that must show
        # up as a recorded sync failure, not a 500 on this endpoint.
        instance.last_sync_status = "error"
        instance.last_sync_message = str(exc)[:500]

    instance.last_sync_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(instance)
    return {"connector": instance.to_dict(), "ingested": len(events), "skipped": skipped}


def _slack_authorize_redirect_uri(request: Request) -> str:
    # Must byte-for-byte match the "Redirect URLs" entry configured on the
    # Slack app, both here and in exchange_code_for_token below - Slack
    # rejects a token exchange whose redirect_uri doesn't match the one used
    # on the authorize step.
    return str(request.base_url).rstrip("/") + "/connectors/slack/callback"


@app.get("/connectors/slack/authorize")
def slack_authorize(
    request: Request,
    token: str = Query(..., description="Access token - passed as a query param since this is a full-page browser redirect, not a fetch()"),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    """Step 1 of the OAuth install: an admin clicks 'Connect to Slack' in
    the Integrations page, which is a plain <a href> navigation (no
    Authorization header on a browser redirect), so the JWT travels as a
    query param instead - same reasoning as the /ws/agent-runs WebSocket
    auth just above."""
    user_id = decode_token(token, "access")
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    if user.role not in (Role.owner.value, Role.admin.value):
        raise HTTPException(status_code=403, detail="Only an organization owner or admin can connect Slack")

    state = sign_oauth_state(user.organization_id, user.id)
    url = build_authorize_url(state, _slack_authorize_redirect_uri(request))
    return RedirectResponse(url)


@app.get("/connectors/slack/callback")
def slack_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    db: Session = Depends(get_db),
) -> RedirectResponse:
    """Step 2: Slack redirects the admin's browser here after they approve
    the install on Slack's own consent screen - unauthenticated by design
    (Slack, not our frontend, drives this request), so `state` (see
    app/slack_oauth.py) is the only thing re-associating this callback with
    the organization/admin that started the flow."""
    if error or not code or not state:
        return RedirectResponse(f"{FRONTEND_URL}/integrations?slack=error")

    try:
        claims = verify_oauth_state(state)
    except Exception:
        return RedirectResponse(f"{FRONTEND_URL}/integrations?slack=error")

    try:
        token_response = exchange_code_for_token(code, _slack_authorize_redirect_uri(request))
    except Exception:
        return RedirectResponse(f"{FRONTEND_URL}/integrations?slack=error")

    if not token_response.get("ok"):
        return RedirectResponse(f"{FRONTEND_URL}/integrations?slack=error")

    organization_id = claims["org_id"]
    team = token_response.get("team", {})
    incoming_webhook = token_response.get("incoming_webhook", {})
    config = {
        "access_token": token_response.get("access_token"),
        "team_id": team.get("id"),
        "team_name": team.get("name"),
        "bot_user_id": token_response.get("bot_user_id"),
        "channel_id": incoming_webhook.get("channel_id"),
        "channel_name": incoming_webhook.get("channel"),
        "incoming_webhook_url": incoming_webhook.get("url"),
        "installed_by_user_id": claims["user_id"],
    }

    # Re-installing (e.g. to change the channel) updates the existing row
    # rather than creating a duplicate connector for the same org+workspace.
    existing = (
        db.query(ConnectorInstance)
        .filter(ConnectorInstance.organization_id == organization_id, ConnectorInstance.plugin_key == "slack")
        .first()
    )
    if existing:
        # A reinstall must never wipe out channel routing an admin already
        # configured (via PATCH /connectors/{id}) - carry forward any
        # "*_channel"/"*_channel_id" keys instead of only using the fresh
        # OAuth response, which knows nothing about them.
        preserved_channels = {k: v for k, v in (existing.config or {}).items() if "_channel" in k}
        existing.config = {**config, **preserved_channels}
        existing.enabled = True
        existing.name = f"Slack ({team.get('name', 'workspace')})"
    else:
        # A brand-new install: auto-create the four optional secondary
        # channels so this org gets a fully working multi-channel setup
        # immediately, with nothing for the admin to manually configure -
        # see slack_bot.py's provision_default_channels for what this does
        # if channel creation fails or the channels:manage scope is missing
        # (fails open: install still succeeds, those roles just stay unset).
        config.update(provision_default_channels(config["access_token"]))
        db.add(ConnectorInstance(
            organization_id=organization_id,
            plugin_key="slack",
            name=f"Slack ({team.get('name', 'workspace')})",
            config=config,
        ))
    db.commit()

    return RedirectResponse(f"{FRONTEND_URL}/integrations?slack=connected")


async def _read_verified_slack_body(request: Request) -> bytes:
    body = await request.body()
    timestamp = request.headers.get("X-Slack-Request-Timestamp", "")
    signature = request.headers.get("X-Slack-Signature", "")
    if not verify_slack_signature(timestamp, body, signature):
        raise HTTPException(status_code=401, detail="Invalid Slack request signature")
    return body


@app.post("/slack/commands")
async def slack_commands(request: Request, db: Session = Depends(get_db)) -> dict:
    """The single endpoint behind every `/sentraops ...` slash command -
    Slack always POSTs form-encoded data here regardless of which command
    was typed; the command text itself (e.g. "investigate 421") is what
    branches the behavior (see app/slack_bot.py.handle_slash_command)."""
    body = await _read_verified_slack_body(request)
    form = parse_qs(body.decode())
    team_id = form.get("team_id", [""])[0]
    text = form.get("text", [""])[0]
    return handle_slash_command(db, team_id, text)


@app.post("/slack/interactions")
async def slack_interactions(request: Request, db: Session = Depends(get_db)) -> dict:
    """Backs every interactive button click (Investigate / Approve / Reject)
    from messages app/slack_bot.py posts. Slack expects an HTTP 200 within
    3 seconds; the actual result is best-effort posted back to `response_url`
    so a slow investigation kickoff doesn't need to block this response."""
    body = await _read_verified_slack_body(request)
    form = parse_qs(body.decode())
    raw_payload = form.get("payload", ["{}"])[0]
    payload = json.loads(raw_payload)

    team_id = (payload.get("team") or {}).get("id", "")
    slack_user = (payload.get("user") or {}).get("username", "someone")
    response_url = payload.get("response_url")
    actions = payload.get("actions") or []
    if not actions:
        return {}

    action = actions[0]
    action_id = action.get("action_id")
    value = action.get("value", "")

    if action_id == "investigate_incident":
        result_text = handle_investigate_button(db, team_id, value)
    elif action_id == "review_action":
        result_text = handle_review_action_button(db, team_id, value, slack_user)
    else:
        return {}

    if response_url:
        try:
            httpx.post(response_url, json={"replace_original": False, "text": result_text}, timeout=5)
        except httpx.HTTPError:
            pass
    return {}


class ResponseActionInstanceCreate(BaseModel):
    plugin_key: str
    name: str
    config: dict = {}


@app.post("/response-action-instances")
def create_response_action_instance(
    payload: ResponseActionInstanceCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin)),
) -> dict:
    try:
        plugin_registry.get_action(payload.plugin_key)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    instance = ResponseActionInstance(
        organization_id=user.organization_id,
        plugin_key=payload.plugin_key,
        name=payload.name,
        config=payload.config,
    )
    db.add(instance)
    db.commit()
    db.refresh(instance)
    return instance.to_dict()


@app.get("/response-action-instances")
def list_response_action_instances(
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    instances = (
        db.query(ResponseActionInstance).filter(ResponseActionInstance.organization_id == user.organization_id).all()
    )
    return {"actions": [a.to_dict() for a in instances]}


@app.post("/proposed-actions/{action_id}/execute")
def execute_proposed_action(
    action_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst)),
) -> dict:
    """Dispatches an already-approved action to every enabled
    ResponseActionInstance configured for its category. Still no
    auto-execution anywhere: this endpoint itself is the human action,
    fired only after a separate human already approved the action via
    PATCH /proposed-actions/{id}."""
    action = _get_scoped_or_404(db, ProposedAction, action_id, user.organization_id, "Proposed action not found")
    if action.status != "approved":
        raise HTTPException(status_code=400, detail=f"Action must be approved before execution (current: {action.status})")

    instances = (
        db.query(ResponseActionInstance)
        .filter(ResponseActionInstance.organization_id == user.organization_id, ResponseActionInstance.enabled.is_(True))
        .all()
    )
    matching = [i for i in instances if action.category in plugin_registry.get_action(i.plugin_key).categories]
    if not matching:
        raise HTTPException(
            status_code=400, detail="No enabled response-action integration configured for this action's category"
        )

    # Enriches the base action fields with incident context so integrations
    # (Jira/ServiceNow/webhook) can render a ticket/message that's actually
    # useful to whoever picks it up, not just a bare category + incident id.
    action_payload = action.to_dict()
    action_payload.update({
        "incident_title": action.incident.title,
        "risk_level": action.incident.risk_level,
        "priority": action.incident.priority,
        "affected_hosts": action.incident.affected_hosts,
        "affected_users": action.incident.affected_users,
        "incident_url": f"{FRONTEND_URL}/incidents/{action.incident_id}",
        "assignee_email": action.incident.assignee.email if action.incident.assignee else None,
    })

    results = []
    all_ok = True
    for instance in matching:
        plugin = plugin_registry.get_action(instance.plugin_key)
        ok, message = plugin.execute(instance.config or {}, action_payload)
        results.append({"integration": instance.name, "ok": ok, "message": message})
        all_ok = all_ok and ok

    action.status = "executed" if all_ok else "execution_failed"
    action.executed_at = datetime.now(timezone.utc)
    action.execution_result = json.dumps(results)
    db.commit()
    db.refresh(action)
    return action.to_dict()


_JIRA_ISSUE_KEY_RE = re.compile(r"Created Jira issue ([A-Z][A-Z0-9]*-\d+)")


@app.get("/connectors/jira/webhook-url")
def get_jira_webhook_url(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin)),
) -> dict:
    """Returns the org-specific URL to paste into a Jira Automation rule
    (trigger: issue transitioned) so that resolving a Jira ticket closes the
    SentraOps incident it was created for. The secret lives in the URL path
    itself, not a header - Jira Automation's webhook action can't set custom
    headers on the free/standard tier, so this is the same "secret-URL"
    pattern Slack/Discord incoming webhooks use."""
    org = db.get(Organization, user.organization_id)
    if org.jira_webhook_secret is None:
        org.jira_webhook_secret = secrets.token_urlsafe(32)
        db.commit()
        db.refresh(org)
    base = str(request.base_url).rstrip("/")
    return {"webhook_url": f"{base}/webhooks/jira/{org.slug}/{org.jira_webhook_secret}"}


@app.post("/webhooks/jira/{org_slug}/{secret}")
@limiter.limit("20/minute")
async def jira_status_webhook(org_slug: str, secret: str, request: Request, db: Session = Depends(get_db)) -> dict:
    """Public endpoint a Jira Automation rule POSTs to on issue transition.
    No auth dependency - the org+secret in the URL path is the auth, same as
    the OAuth-free "secret URL" Slack/Discord incoming webhooks use, since
    Jira Automation's webhook action can't be configured to sign requests or
    send an Authorization header on every plan. Rate-limited by IP (this is
    unauthenticated, so that's the only key slowapi can use) as defense in
    depth against brute-forcing the secret, on top of it being an
    unguessable 32-byte token.

    Always returns 200 (even on "no match found") so Jira doesn't disable
    the webhook after a few non-2xx responses - a skipped/unmatched event is
    a normal, expected outcome here (e.g. a ticket unrelated to SentraOps),
    not a failure worth retrying."""
    org = db.query(Organization).filter(Organization.slug == org_slug).first()
    if org is None or org.jira_webhook_secret is None or not secrets.compare_digest(org.jira_webhook_secret, secret):
        raise HTTPException(status_code=404, detail="Not found")

    try:
        payload = await request.json()
    except json.JSONDecodeError:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    issue = payload.get("issue") or {}
    if not isinstance(issue, dict):
        issue = {}
    issue_key = issue.get("key")
    status = issue.get("fields", {}).get("status") if isinstance(issue.get("fields"), dict) else None
    status_category = (status or {}).get("statusCategory") if isinstance(status, dict) else None
    is_done = isinstance(status_category, dict) and status_category.get("key") == "done"
    if not issue_key or not is_done:
        return {"ok": True, "matched": False, "message": "Not a 'done' transition, no action taken", "received_keys": list(payload.keys())}

    candidates = (
        db.query(ProposedAction)
        .filter(ProposedAction.organization_id == org.id, ProposedAction.execution_result.isnot(None))
        .all()
    )
    matched_action = None
    for candidate in candidates:
        try:
            results = json.loads(candidate.execution_result)
        except (TypeError, ValueError):
            continue
        for result in results:
            match = _JIRA_ISSUE_KEY_RE.search(result.get("message", ""))
            if match and match.group(1) == issue_key:
                matched_action = candidate
                break
        if matched_action:
            break

    if matched_action is None:
        return {"ok": True, "matched": False, "message": f"No SentraOps action found for Jira issue {issue_key}"}

    incident = matched_action.incident
    if incident.status == "closed":
        return {"ok": True, "matched": True, "already_closed": True, "incident_id": incident.id}

    incident.status = "closed"
    incident.closed_at = datetime.now(timezone.utc)
    record_audit(
        db,
        org.id,
        actor_email=f"jira-webhook:{issue_key}",
        action="incident_closed_via_jira",
        details={"incident_id": incident.id, "jira_issue_key": issue_key},
    )
    db.commit()
    return {"ok": True, "matched": True, "incident_id": incident.id, "message": f"Closed incident #{incident.id} via Jira {issue_key}"}


@app.get("/threat-intel/indicators")
def list_threat_indicators(
    q: str | None = None,
    indicator_type: Literal["ip", "domain", "url", "hash"] | None = None,
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    """The shared Threat Intel Hub - deliberately not org-scoped, unlike
    every other list endpoint in this file (see ThreatIndicator's
    docstring): every tenant's correlation engine matches against the same
    indicator table, the way a commercial TI feed is one subscription
    shared across customers, not a per-customer copy."""
    indicators = search_indicators(db, q=q, indicator_type=indicator_type, limit=limit)
    return {"indicators": [i.to_dict() for i in indicators]}


@app.post("/threat-intel/sync")
def sync_threat_intel(
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst)),
) -> dict:
    """Pulls the real URLhaus feed into the shared indicator table right
    now. Not org-scoped for the same reason listing isn't - one sync
    benefits every tenant's correlation engine, not just the caller's."""
    try:
        count = sync_urlhaus(db)
    except Exception as exc:
        # A third-party feed is a real system boundary - it will
        # sometimes be down/rate-limited, and that must surface as a
        # clean error, not a 500.
        raise HTTPException(status_code=502, detail=f"URLhaus sync failed: {exc}")
    return {"synced": count}


@app.post("/threat-intel/graph/sync")
def sync_threat_intel_graph(
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst)),
) -> dict:
    """Rebuilds the shared Indicator/Tag/Source relationship graph in
    Neo4j from the current indicator table + every org's real incident
    matches - makes the Threat Intel Hub a queryable graph, not just a
    flat list."""
    try:
        return resync_indicator_graph(db)
    except (Neo4jError, ServiceUnavailable):
        raise _graph_unavailable()


@app.get("/threat-intel/graph")
def threat_intel_graph(
    limit: int = Query(default=300, ge=1, le=1000),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    try:
        return get_indicator_graph(user.organization_id, limit)
    except (Neo4jError, ServiceUnavailable):
        raise _graph_unavailable()


def _graph_unavailable() -> HTTPException:
    return HTTPException(status_code=503, detail="Graph database isn't available - has /graph/sync been run?")


@app.post("/graph/sync")
def sync_graph(
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst)),
) -> dict:
    """Rebuilds the Neo4j attack graph from the current Postgres state -
    Host/User/IP/Incident nodes and the relationships between them, derived
    from every correlated event. Postgres stays the source of truth; this
    is a read-optimized view for graph-shaped questions (blast radius,
    shared-entity paths across incidents) the relational schema can't
    answer well. Full resync rather than incremental sync-on-ingest -
    simple, and doesn't couple the ingestion path to a second database."""
    try:
        return resync_graph(db, user.organization_id)
    except (Neo4jError, ServiceUnavailable):
        raise _graph_unavailable()


@app.get("/graph/incident/{incident_id}")
def incident_graph(
    incident_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    """The Host/User/IP entities tied to one incident and the edges
    between them - the "Attack Graph" tab on an incident."""
    incident = _get_scoped_or_404(db, Incident, incident_id, user.organization_id, "Incident not found")
    try:
        return get_incident_subgraph(incident.id, user.organization_id)
    except (Neo4jError, ServiceUnavailable):
        raise _graph_unavailable()


@app.get("/graph/entity")
def entity_blast_radius(
    type: Literal["host", "user", "ip"],
    value: str,
    hops: int = Query(default=2, ge=1, le=4),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    """Everything reachable from one host/user/IP within N hops, across
    every incident it appears in - reveals connections a single incident's
    own view never shows (e.g. the same source IP hitting a different
    host in an unrelated incident three weeks later)."""
    try:
        return get_entity_blast_radius(type, value, user.organization_id, hops)
    except (Neo4jError, ServiceUnavailable):
        raise _graph_unavailable()


@app.get("/digital-twin/simulate")
def digital_twin_simulate(
    type: Literal["host", "user", "ip"],
    value: str,
    hops: int = Query(default=2, ge=1, le=4),
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    """Real, free (no LLM call) 'what happens if this is compromised'
    simulation - the actual attack-graph blast radius cross-referenced
    against this org's real asset criticality data, computed fresh on
    every request."""
    try:
        return simulate_compromise(db, type, value, user.organization_id, hops)
    except (Neo4jError, ServiceUnavailable):
        raise _graph_unavailable()


@app.post("/digital-twin/narrative")
@limiter.limit("10/minute")
def digital_twin_narrative(
    request: Request,
    type: Literal["host", "user", "ip"],
    value: str,
    hops: int = Query(default=2, ge=1, le=4),
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    """One Groq call turning the real simulation above into a lateral-
    movement/impact/recovery narrative - same 503/502 distinction every
    other AI endpoint uses."""
    try:
        simulation = simulate_compromise(db, type, value, user.organization_id, hops)
    except (Neo4jError, ServiceUnavailable):
        raise _graph_unavailable()
    try:
        narrative = generate_twin_narrative(simulation)
    except ChatConfigError:
        raise HTTPException(status_code=503, detail="AI digital twin narrative isn't configured - set GROQ_API_KEY")
    except ChatProviderError as exc:
        raise HTTPException(status_code=502, detail=f"AI provider error: {exc}")
    return {"simulation": simulation, "narrative": narrative}


@app.get("/graph")
def full_graph(
    limit: int = Query(default=300, ge=1, le=1000),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    """A capped view of the whole attack graph - the general explorer."""
    try:
        return get_full_graph(user.organization_id, limit)
    except (Neo4jError, ServiceUnavailable):
        raise _graph_unavailable()


class IncidentUpdate(BaseModel):
    status: Literal["open", "closed"] | None = None
    priority: Literal["low", "medium", "high", "critical"] | None = None
    assignee_id: int | None = None


@app.patch("/incidents/{incident_id}")
def update_incident(
    incident_id: int,
    payload: IncidentUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst)),
) -> dict:
    incident = _get_scoped_or_404(db, Incident, incident_id, user.organization_id, "Incident not found")

    updates = payload.model_dump(exclude_unset=True)

    for field in ("status", "priority"):
        if field in updates and updates[field] is None:
            raise HTTPException(status_code=400, detail=f"{field} cannot be null")

    old_status = incident.status
    status_changed = "status" in updates and updates["status"] != old_status

    if "status" in updates:
        incident.status = updates["status"]
        incident.closed_at = datetime.now(timezone.utc) if updates["status"] == "closed" else None

    if "priority" in updates:
        incident.priority = updates["priority"]

    newly_assigned = None
    if "assignee_id" in updates:
        assignee_id = updates["assignee_id"]
        if assignee_id is not None:
            # organization_id check: an incident must never be assignable to
            # a user outside the incident's own organization.
            assignee = _get_scoped_or_404(db, User, assignee_id, user.organization_id, "Assignee not found")
            db.add(Notification(
                user_id=assignee.id,
                message=f"You've been assigned incident #{incident.id}: {incident.title}",
                incident_id=incident.id,
            ))
            newly_assigned = assignee
        incident.assignee_id = assignee_id

    db.commit()
    db.refresh(incident)

    if newly_assigned:
        try:
            notify_assignment(db, incident, newly_assigned)
        except Exception:
            pass
    if status_changed:
        try:
            notify_status_change(db, incident, user, old_status, incident.status)
        except Exception:
            pass

    return incident.to_detail_dict()


class CommentCreate(BaseModel):
    body: str


@app.post("/incidents/{incident_id}/comments")
def add_incident_comment(
    incident_id: int,
    payload: CommentCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst)),
) -> dict:
    incident = _get_scoped_or_404(db, Incident, incident_id, user.organization_id, "Incident not found")

    comment = IncidentComment(incident_id=incident.id, author_id=user.id, body=payload.body)
    db.add(comment)
    db.commit()
    db.refresh(comment)

    try:
        notify_comment(db, incident, user, payload.body)
    except Exception:
        pass

    return comment.to_dict()


@app.get("/assets")
def list_assets(
    q: str | None = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    query = db.query(Asset).filter(Asset.organization_id == user.organization_id)
    if q:
        like = f"%{q}%"
        query = query.filter(or_(Asset.host.ilike(like), Asset.department.ilike(like), Asset.owner.ilike(like)))

    total = query.count()
    assets = query.order_by(Asset.last_seen.desc()).offset(offset).limit(min(limit, 500)).all()
    return {"total": total, "assets": [a.to_dict() for a in assets]}


class AssetUpdate(BaseModel):
    os: str | None = None
    department: str | None = None
    owner: str | None = None
    criticality: Literal["low", "medium", "high", "critical"] | None = None


@app.patch("/assets/{asset_id}")
def update_asset(
    asset_id: int,
    payload: AssetUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst)),
) -> dict:
    asset = _get_scoped_or_404(db, Asset, asset_id, user.organization_id, "Asset not found")

    updates = payload.model_dump(exclude_unset=True)
    if updates.get("criticality", "unset") is None:
        raise HTTPException(status_code=400, detail="criticality cannot be null")

    for field, value in updates.items():
        setattr(asset, field, value)

    db.commit()
    db.refresh(asset)
    return asset.to_dict()


@app.get("/stats")
def get_stats(
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    """Dashboard aggregates computed over the whole table via SQL
    COUNT/GROUP BY, not a capped list fetched and counted client-side - the
    dashboard used to sample only the 500 most recent events for its
    severity chart, which quietly went inaccurate past that many rows.
    Everything scoped to the caller's own organization."""
    org_id = user.organization_id
    total_events = db.query(Event).filter(Event.organization_id == org_id).count()
    total_incidents = db.query(Incident).filter(Incident.organization_id == org_id).count()
    open_incidents = db.query(Incident).filter(Incident.organization_id == org_id, Incident.status == "open").count()
    critical_incidents = (
        db.query(Incident).filter(Incident.organization_id == org_id, Incident.risk_level == "critical").count()
    )

    severity_counts = dict(
        db.query(Event.severity, func.count(Event.id))
        .filter(Event.organization_id == org_id)
        .group_by(Event.severity)
        .all()
    )
    severity_distribution = {s: severity_counts.get(s, 0) for s in ("low", "medium", "high", "critical")}

    recent_incidents = (
        db.query(Incident).filter(Incident.organization_id == org_id).order_by(Incident.created_at.desc()).limit(5).all()
    )

    return {
        "total_events": total_events,
        "total_incidents": total_incidents,
        "open_incidents": open_incidents,
        "critical_incidents": critical_incidents,
        "severity_distribution": severity_distribution,
        "recent_incidents": [i.to_summary_dict() for i in recent_incidents],
    }


@app.get("/executive/summary")
def executive_summary(
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    return get_executive_summary(db, user.organization_id)


@app.post("/executive/briefing")
@limiter.limit("10/minute")
def executive_briefing(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    """One Groq call producing a plain-language leadership briefing,
    grounded strictly in the real aggregates from executive_summary above -
    same 503 (not configured) vs 502 (provider failed) distinction every
    other AI endpoint in this file uses."""
    summary = get_executive_summary(db, user.organization_id)
    try:
        briefing = generate_briefing(summary)
    except ChatConfigError:
        raise HTTPException(status_code=503, detail="AI briefing isn't configured - set GROQ_API_KEY")
    except ChatProviderError as exc:
        raise HTTPException(status_code=502, detail=f"AI provider error: {exc}")
    return {"summary": summary, "briefing": briefing}


@app.get("/compliance/controls")
def list_compliance_controls(
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    """Each control's status is computed fresh against this org's real
    data every call (see app/compliance.py's check registry) - nothing is
    cached, so a control can never report a stale pass/fail."""
    controls = evaluate_controls(db, user.organization_id)
    return {"controls": controls}


@app.post("/compliance/report")
@limiter.limit("10/minute")
def compliance_report(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst)),
) -> dict:
    controls = evaluate_controls(db, user.organization_id)
    try:
        report = generate_compliance_report(controls)
    except ChatConfigError:
        raise HTTPException(status_code=503, detail="AI compliance report isn't configured - set GROQ_API_KEY")
    except ChatProviderError as exc:
        raise HTTPException(status_code=502, detail=f"AI provider error: {exc}")

    try:
        notify_compliance_report(db, user.organization_id, report)
    except Exception:
        pass

    return {"controls": controls, "report": report}


@app.get("/predictive/summary")
def predictive_summary(
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    """Real, free (no LLM call), computed-fresh-on-every-request signals:
    an IsolationForest anomaly pass over this org's own event history,
    a privilege-escalation trend, and a risk-score drift comparison."""
    return get_predictive_summary(db, user.organization_id)


@app.post("/predictive/briefing")
@limiter.limit("10/minute")
def predictive_briefing(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    """One Groq call interpreting the real statistical signals from
    predictive_summary into a forward-looking ('likely', not 'happened')
    narrative - same 503/502 distinction every other AI endpoint uses."""
    summary = get_predictive_summary(db, user.organization_id)
    try:
        briefing = generate_predictive_briefing(summary)
    except ChatConfigError:
        raise HTTPException(status_code=503, detail="AI predictive briefing isn't configured - set GROQ_API_KEY")
    except ChatProviderError as exc:
        raise HTTPException(status_code=502, detail=f"AI provider error: {exc}")
    return {"summary": summary, "briefing": briefing}


@app.get("/observability/ai-summary")
def ai_observability_summary(
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    """Real per-feature AI usage/cost/latency/success-rate, read live off
    this process's own Prometheus counters (app/observability.py) - the
    same numbers Grafana would show, reshaped for the frontend."""
    return get_ai_observability_summary()


@app.get("/marketplace/playbooks")
def list_marketplace_playbooks(
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    installed_ids = {p.id for p in list_installed_playbooks(db, user.organization_id)}
    return {
        "playbooks": [{**p.to_dict(), "installed": p.id in installed_ids} for p in list_playbooks(db)],
    }


@app.post("/marketplace/playbooks/{playbook_id}/install")
def install_marketplace_playbook(
    playbook_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin)),
) -> dict:
    playbook = db.get(PlaybookTemplate, playbook_id)
    if playbook is None:
        raise HTTPException(status_code=404, detail="Playbook not found")
    install_playbook(db, user.organization_id, playbook_id)
    db.commit()
    return {**playbook.to_dict(), "installed": True}


@app.post("/marketplace/playbooks/{playbook_id}/uninstall")
def uninstall_marketplace_playbook(
    playbook_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin)),
) -> dict:
    playbook = db.get(PlaybookTemplate, playbook_id)
    if playbook is None:
        raise HTTPException(status_code=404, detail="Playbook not found")
    uninstall_playbook(db, user.organization_id, playbook_id)
    return {**playbook.to_dict(), "installed": False}


@app.get("/command-center/queue")
def command_center_queue(
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    return get_command_center_queue(db, user.organization_id)


class ShiftNoteCreate(BaseModel):
    body: str


@app.post("/shift-notes")
def create_shift_note(
    payload: ShiftNoteCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst)),
) -> dict:
    if not payload.body.strip():
        raise HTTPException(status_code=422, detail="body cannot be empty")
    note = ShiftNote(organization_id=user.organization_id, author_id=user.id, body=payload.body.strip())
    db.add(note)
    db.commit()
    db.refresh(note)
    return note.to_dict()


@app.get("/shift-notes")
def list_shift_notes(
    limit: int = Query(20, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    notes = (
        db.query(ShiftNote)
        .filter(ShiftNote.organization_id == user.organization_id)
        .order_by(ShiftNote.created_at.desc())
        .limit(limit)
        .all()
    )
    return {"notes": [n.to_dict() for n in notes]}


@app.get("/search")
def search(
    q: str = Query(..., min_length=1),
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    like = f"%{q}%"
    org_id = user.organization_id

    events = (
        db.query(Event)
        .filter(
            Event.organization_id == org_id,
            or_(Event.host.ilike(like), Event.username.ilike(like), Event.message.ilike(like), Event.source_ip.ilike(like)),
        )
        .order_by(Event.timestamp.desc())
        .limit(10)
        .all()
    )
    incidents = (
        db.query(Incident)
        .filter(Incident.organization_id == org_id, Incident.title.ilike(like))
        .order_by(Incident.created_at.desc())
        .limit(10)
        .all()
    )
    assets = (
        db.query(Asset)
        .filter(
            Asset.organization_id == org_id,
            or_(Asset.host.ilike(like), Asset.department.ilike(like), Asset.owner.ilike(like)),
        )
        .order_by(Asset.host)
        .limit(10)
        .all()
    )

    return {
        "events": [e.to_dict() for e in events],
        "incidents": [i.to_summary_dict() for i in incidents],
        "assets": [a.to_dict() for a in assets],
    }


@app.get("/rag/search")
def semantic_search(
    q: str = Query(..., min_length=1),
    content_type: Literal["event", "incident", "knowledge_chunk"] | None = None,
    k: int = 5,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    """Meaning-based search (embeddings + cosine similarity), unlike
    /search above which is a plain SQL ILIKE substring match. This is the
    retrieval half of RAG - no LLM call here, just ranked evidence. Milestone
    2's chat endpoint will call this same function to ground its answers."""
    return {"query": q, "results": rag_search(db, user.organization_id, q, content_type=content_type, k=min(k, 20))}


class ChatRequest(BaseModel):
    question: str


@app.post("/chat")
@limiter.limit("20/minute")
def chat(
    request: Request,
    payload: ChatRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    """RAG in full: semantic search for evidence, then a Groq call grounded
    in that evidence. Distinguishes a missing API key (503 - not configured)
    from a real provider failure (502 - configured but Groq itself failed)."""
    if not payload.question.strip():
        raise HTTPException(status_code=422, detail="question cannot be empty")

    evidence = rag_search(db, user.organization_id, payload.question, k=8)

    try:
        answer = answer_question(payload.question, evidence)
    except ChatConfigError:
        raise HTTPException(status_code=503, detail="AI chat isn't configured - set GROQ_API_KEY")
    except ChatProviderError as exc:
        raise HTTPException(status_code=502, detail=f"AI provider error: {exc}")

    confidence = compute_dual_evidence_confidence(db, user.organization_id, evidence)

    return {"question": payload.question, "answer": answer, "sources": evidence, **confidence}


class QueryRequest(BaseModel):
    question: str
    limit: int = 50
    offset: int = 0


@app.post("/query")
@limiter.limit("20/minute")
def natural_language_query(
    request: Request,
    payload: QueryRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.owner, Role.admin, Role.soc_manager, Role.analyst, Role.auditor, Role.executive)),
) -> dict:
    """Translates a natural-language question into the SAME structured filter
    fields /events already accepts (event_type, severity, username, host,
    source_ip, q) - the LLM only ever picks values for a fixed set of known
    fields, it never generates SQL/KQL/any query language, so there's no
    injection surface here regardless of what the question contains."""
    if not payload.question.strip():
        raise HTTPException(status_code=422, detail="question cannot be empty")

    try:
        filters = translate_query(payload.question)
    except ChatConfigError:
        raise HTTPException(status_code=503, detail="AI chat isn't configured - set GROQ_API_KEY")
    except ChatProviderError as exc:
        raise HTTPException(status_code=502, detail=f"AI provider error: {exc}")

    query = _filter_events(
        db,
        user.organization_id,
        filters["q"],
        filters["event_type"],
        filters["severity"],
        filters["username"],
        filters["host"],
        filters["source_ip"],
    )
    total = query.count()
    events = query.order_by(Event.timestamp.desc()).offset(payload.offset).limit(min(payload.limit, 500)).all()

    return {
        "question": payload.question,
        "filters": filters,
        "total": total,
        "events": [e.to_dict() for e in events],
    }


@app.get("/notifications")
def list_notifications(
    unread_only: bool = False,
    limit: int = 50,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    query = db.query(Notification).filter(Notification.user_id == user.id)
    if unread_only:
        query = query.filter(Notification.is_read.is_(False))

    unread_count = db.query(Notification).filter(Notification.user_id == user.id, Notification.is_read.is_(False)).count()
    notifications = query.order_by(Notification.created_at.desc()).limit(min(limit, 200)).all()

    return {"unread_count": unread_count, "notifications": [n.to_dict() for n in notifications]}


@app.patch("/notifications/{notification_id}/read")
def mark_notification_read(
    notification_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    notification = db.get(Notification, notification_id)
    if not notification or notification.user_id != user.id:
        raise HTTPException(status_code=404, detail="Notification not found")

    notification.is_read = True
    db.commit()
    db.refresh(notification)
    return notification.to_dict()


@app.post("/notifications/read-all")
def mark_all_notifications_read(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    db.query(Notification).filter(Notification.user_id == user.id, Notification.is_read.is_(False)).update({"is_read": True})
    db.commit()
    return {"status": "ok"}
