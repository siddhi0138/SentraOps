import csv
import io
import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile
from pydantic import BaseModel
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.db import get_db, init_db
from app.db_models import Event
from app.ingestion import ingest
from app.models import LogEvent
from app.pipeline import SecurityPipeline
from app.simulate import get_scenario

SAMPLE_LOGS_PATH = Path(__file__).resolve().parent.parent / "data" / "sample_logs.json"
legacy_pipeline = SecurityPipeline()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="CyberSentinel AI", version="0.2.0", lifespan=lifespan)


class IngestRequest(BaseModel):
    logs: list[Any]


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/investigate")
def investigate() -> dict:
    """Legacy in-memory correlation demo. Will be replaced by a correlation
    engine that runs over persisted /events once step 3 lands."""
    raw_logs = json.loads(SAMPLE_LOGS_PATH.read_text())
    logs = [LogEvent(**entry) for entry in raw_logs]
    incident = legacy_pipeline.run(logs)
    return incident.model_dump()


@app.post("/ingest/{source_type}")
def ingest_logs(source_type: str, payload: IngestRequest, db: Session = Depends(get_db)) -> dict:
    try:
        events, skipped = ingest(db, source_type, payload.logs)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return {"ingested": len(events), "skipped": skipped, "events": [e.to_dict() for e in events]}


@app.post("/ingest/upload")
async def ingest_upload(
    source_type: str = Query(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> dict:
    content = (await file.read()).decode("utf-8")

    if file.filename and file.filename.lower().endswith(".csv"):
        raw_items: list[Any] = list(csv.DictReader(io.StringIO(content)))
    else:
        parsed = json.loads(content)
        raw_items = parsed if isinstance(parsed, list) else [parsed]

    try:
        events, skipped = ingest(db, source_type, raw_items)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return {"ingested": len(events), "skipped": skipped}


@app.post("/simulate/{scenario}")
def simulate(scenario: str, db: Session = Depends(get_db)) -> dict:
    try:
        logs_by_source = get_scenario(scenario)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    results = {}
    for source_type, raw_items in logs_by_source.items():
        events, skipped = ingest(db, source_type, raw_items)
        results[source_type] = {"ingested": len(events), "skipped": skipped}

    return {"scenario": scenario, "sources": results}


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
) -> dict:
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

    total = query.count()
    events = query.order_by(Event.timestamp.desc()).offset(offset).limit(min(limit, 500)).all()

    return {"total": total, "events": [e.to_dict() for e in events]}
