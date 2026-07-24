import json
from pathlib import Path

from fastapi import FastAPI

from app.models import LogEvent
from app.pipeline import SecurityPipeline

app = FastAPI(title="CyberSentinel AI", version="0.1.0")
pipeline = SecurityPipeline()

SAMPLE_LOGS_PATH = Path(__file__).resolve().parent.parent / "data" / "sample_logs.json"


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/investigate")
def investigate() -> dict:
    raw_logs = json.loads(SAMPLE_LOGS_PATH.read_text())
    logs = [LogEvent(**entry) for entry in raw_logs]
    incident = pipeline.run(logs)
    return incident.model_dump()
