import csv
import io
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import Depends, FastAPI, File, HTTPException, Query, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.auth import (
    Role,
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
from app.db_models import Asset, Event, Incident, IncidentComment, Notification, User
from app.ai import ChatConfigError, ChatProviderError, answer_question, explain_incident
from app.ingestion import ingest
from app.rag import search as rag_search
from app.simulate import get_scenario


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="CyberSentinel AI", version="0.2.0", lifespan=lifespan)

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


class IngestRequest(BaseModel):
    logs: list[Any]


def _user_out(user: User) -> UserOut:
    return UserOut(id=user.id, email=user.email, role=user.role, is_active=user.is_active)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/auth/register", response_model=UserOut)
def register(payload: UserCreate, db: Session = Depends(get_db)) -> UserOut:
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    # Bootstrap: the very first account becomes admin so there's always
    # someone who can promote/manage everyone else. Later signups default
    # to viewer until an admin raises their role.
    role = Role.admin.value if db.query(User).count() == 0 else Role.viewer.value

    user = User(email=payload.email, hashed_password=hash_password(payload.password), role=role)
    db.add(user)
    db.commit()
    db.refresh(user)
    return _user_out(user)


@app.post("/auth/login", response_model=TokenPair)
def login(payload: UserLogin, db: Session = Depends(get_db)) -> TokenPair:
    user = db.query(User).filter(User.email == payload.email).first()
    if not user or not user.is_active or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    return TokenPair(access_token=create_access_token(user.id), refresh_token=create_refresh_token(user.id))


@app.post("/auth/refresh", response_model=TokenPair)
def refresh(payload: RefreshRequest, db: Session = Depends(get_db)) -> TokenPair:
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
    _user: User = Depends(require_roles(Role.admin, Role.analyst)),
) -> list[UserOut]:
    # analysts need this to populate the incident-assignee picker; only role
    # changes stay admin-only (see update_user_role below).
    return [_user_out(u) for u in db.query(User).order_by(User.id).all()]


@app.patch("/users/{user_id}/role", response_model=UserOut)
def update_user_role(
    user_id: int,
    payload: RoleUpdate,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_roles(Role.admin)),
) -> UserOut:
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.role = payload.role.value
    db.commit()
    db.refresh(user)
    return _user_out(user)


@app.post("/ingest/upload")
async def ingest_upload(
    source_type: str = Query(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    _user: User = Depends(require_roles(Role.admin, Role.analyst)),
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
        events, skipped = ingest(db, source_type, raw_items)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return {"ingested": len(events), "skipped": skipped}


@app.post("/ingest/{source_type}")
def ingest_logs(
    source_type: str,
    payload: IngestRequest,
    db: Session = Depends(get_db),
    _user: User = Depends(require_roles(Role.admin, Role.analyst)),
) -> dict:
    try:
        events, skipped = ingest(db, source_type, payload.logs)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return {"ingested": len(events), "skipped": skipped, "events": [e.to_dict() for e in events]}


@app.post("/simulate/{scenario}")
def simulate(
    scenario: str,
    db: Session = Depends(get_db),
    _user: User = Depends(require_roles(Role.admin, Role.analyst)),
) -> dict:
    try:
        logs_by_source = get_scenario(scenario)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    results = {}
    for source_type, raw_items in logs_by_source.items():
        events, skipped = ingest(db, source_type, raw_items)
        results[source_type] = {"ingested": len(events), "skipped": skipped}

    return {"scenario": scenario, "sources": results}


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
    q: str | None,
    event_type: str | None,
    severity: str | None,
    username: str | None,
    host: str | None,
    source_ip: str | None,
):
    query = db.query(Event)

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
    _user: User = Depends(require_roles(Role.admin, Role.analyst, Role.viewer)),
) -> dict:
    query = _filter_events(db, q, event_type, severity, username, host, source_ip)
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
    _user: User = Depends(require_roles(Role.admin, Role.analyst, Role.viewer)),
) -> Response:
    events = _filter_events(db, q, event_type, severity, username, host, source_ip).order_by(Event.timestamp.desc()).limit(5000).all()

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


@app.post("/correlate")
def correlate(
    db: Session = Depends(get_db),
    _user: User = Depends(require_roles(Role.admin, Role.analyst)),
) -> dict:
    incidents = run_correlation(db)
    return {"incidents_created": len(incidents), "incidents": [i.to_summary_dict() for i in incidents]}


@app.get("/incidents")
def list_incidents(
    status: str | None = None,
    risk_level: str | None = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    _user: User = Depends(require_roles(Role.admin, Role.analyst, Role.viewer)),
) -> dict:
    query = db.query(Incident)
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
    _user: User = Depends(require_roles(Role.admin, Role.analyst, Role.viewer)),
) -> Response:
    query = db.query(Incident)
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
    _user: User = Depends(require_roles(Role.admin, Role.analyst, Role.viewer)),
) -> dict:
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident.to_detail_dict()


@app.get("/incidents/{incident_id}/report.md")
def download_incident_report(
    incident_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(require_roles(Role.admin, Role.analyst, Role.viewer)),
) -> Response:
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    return Response(
        content=incident.report,
        media_type="text/markdown",
        headers={"Content-Disposition": f"attachment; filename=incident-{incident_id}-report.md"},
    )


@app.get("/incidents/{incident_id}/explain")
def explain_incident_endpoint(
    incident_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(require_roles(Role.admin, Role.analyst, Role.viewer)),
) -> dict:
    """AI-generated explanation, timeline narrative, and structured summary
    for one incident - one Groq call, not persisted (regenerated on
    request), so this reflects the incident's current report every time."""
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    try:
        return explain_incident(incident.report, incident.confidence)
    except ChatConfigError:
        raise HTTPException(status_code=503, detail="AI chat isn't configured - set GROQ_API_KEY")
    except ChatProviderError as exc:
        raise HTTPException(status_code=502, detail=f"AI provider error: {exc}")


class IncidentUpdate(BaseModel):
    status: Literal["open", "closed"] | None = None
    priority: Literal["low", "medium", "high", "critical"] | None = None
    assignee_id: int | None = None


@app.patch("/incidents/{incident_id}")
def update_incident(
    incident_id: int,
    payload: IncidentUpdate,
    db: Session = Depends(get_db),
    _user: User = Depends(require_roles(Role.admin, Role.analyst)),
) -> dict:
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    updates = payload.model_dump(exclude_unset=True)

    for field in ("status", "priority"):
        if field in updates and updates[field] is None:
            raise HTTPException(status_code=400, detail=f"{field} cannot be null")

    if "status" in updates:
        incident.status = updates["status"]
        incident.closed_at = datetime.now(timezone.utc) if updates["status"] == "closed" else None

    if "priority" in updates:
        incident.priority = updates["priority"]

    if "assignee_id" in updates:
        assignee_id = updates["assignee_id"]
        if assignee_id is not None:
            assignee = db.get(User, assignee_id)
            if not assignee:
                raise HTTPException(status_code=404, detail="Assignee not found")
            db.add(Notification(
                user_id=assignee.id,
                message=f"You've been assigned incident #{incident.id}: {incident.title}",
                incident_id=incident.id,
            ))
        incident.assignee_id = assignee_id

    db.commit()
    db.refresh(incident)
    return incident.to_detail_dict()


class CommentCreate(BaseModel):
    body: str


@app.post("/incidents/{incident_id}/comments")
def add_incident_comment(
    incident_id: int,
    payload: CommentCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.admin, Role.analyst)),
) -> dict:
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    comment = IncidentComment(incident_id=incident_id, author_id=user.id, body=payload.body)
    db.add(comment)
    db.commit()
    db.refresh(comment)
    return comment.to_dict()


@app.get("/assets")
def list_assets(
    q: str | None = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    _user: User = Depends(require_roles(Role.admin, Role.analyst, Role.viewer)),
) -> dict:
    query = db.query(Asset)
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
    _user: User = Depends(require_roles(Role.admin, Role.analyst)),
) -> dict:
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

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
    _user: User = Depends(require_roles(Role.admin, Role.analyst, Role.viewer)),
) -> dict:
    """Dashboard aggregates computed over the whole table via SQL
    COUNT/GROUP BY, not a capped list fetched and counted client-side - the
    dashboard used to sample only the 500 most recent events for its
    severity chart, which quietly went inaccurate past that many rows."""
    total_events = db.query(Event).count()
    total_incidents = db.query(Incident).count()
    open_incidents = db.query(Incident).filter(Incident.status == "open").count()
    critical_incidents = db.query(Incident).filter(Incident.risk_level == "critical").count()

    severity_counts = dict(db.query(Event.severity, func.count(Event.id)).group_by(Event.severity).all())
    severity_distribution = {s: severity_counts.get(s, 0) for s in ("low", "medium", "high", "critical")}

    recent_incidents = db.query(Incident).order_by(Incident.created_at.desc()).limit(5).all()

    return {
        "total_events": total_events,
        "total_incidents": total_incidents,
        "open_incidents": open_incidents,
        "critical_incidents": critical_incidents,
        "severity_distribution": severity_distribution,
        "recent_incidents": [i.to_summary_dict() for i in recent_incidents],
    }


@app.get("/search")
def search(
    q: str = Query(..., min_length=1),
    db: Session = Depends(get_db),
    _user: User = Depends(require_roles(Role.admin, Role.analyst, Role.viewer)),
) -> dict:
    like = f"%{q}%"

    events = (
        db.query(Event)
        .filter(or_(Event.host.ilike(like), Event.username.ilike(like), Event.message.ilike(like), Event.source_ip.ilike(like)))
        .order_by(Event.timestamp.desc())
        .limit(10)
        .all()
    )
    incidents = db.query(Incident).filter(Incident.title.ilike(like)).order_by(Incident.created_at.desc()).limit(10).all()
    assets = (
        db.query(Asset)
        .filter(or_(Asset.host.ilike(like), Asset.department.ilike(like), Asset.owner.ilike(like)))
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
    content_type: Literal["event", "incident"] | None = None,
    k: int = 5,
    db: Session = Depends(get_db),
    _user: User = Depends(require_roles(Role.admin, Role.analyst, Role.viewer)),
) -> dict:
    """Meaning-based search (embeddings + cosine similarity), unlike
    /search above which is a plain SQL ILIKE substring match. This is the
    retrieval half of RAG - no LLM call here, just ranked evidence. Milestone
    2's chat endpoint will call this same function to ground its answers."""
    return {"query": q, "results": rag_search(db, q, content_type=content_type, k=min(k, 20))}


class ChatRequest(BaseModel):
    question: str


@app.post("/chat")
def chat(
    payload: ChatRequest,
    db: Session = Depends(get_db),
    _user: User = Depends(require_roles(Role.admin, Role.analyst, Role.viewer)),
) -> dict:
    """RAG in full: semantic search for evidence, then a Groq call grounded
    in that evidence. Distinguishes a missing API key (503 - not configured)
    from a real provider failure (502 - configured but Groq itself failed)."""
    if not payload.question.strip():
        raise HTTPException(status_code=422, detail="question cannot be empty")

    evidence = rag_search(db, payload.question, k=8)

    try:
        answer = answer_question(payload.question, evidence)
    except ChatConfigError:
        raise HTTPException(status_code=503, detail="AI chat isn't configured - set GROQ_API_KEY")
    except ChatProviderError as exc:
        raise HTTPException(status_code=502, detail=f"AI provider error: {exc}")

    return {"question": payload.question, "answer": answer, "sources": evidence}


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
