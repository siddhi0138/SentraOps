# CyberSentinel AI

An AI Security Team for SMEs, built the way a real product would be: a
solid SOC platform first, AI reasoning layered on top of it later.

## Roadmap

```
Milestone 1: CyberSentinel Core       - Foundation SOC (no AI)
Milestone 2: AI Security Analyst      - LLM reasoning over the platform
Milestone 3: Autonomous AI Security Team - Multi-agent investigation
Milestone 4: Enterprise SOC Platform  - Streaming, graph, RBAC, deployment
```

## Milestone 1 progress: CyberSentinel Core

Building this in dependency order, since each layer needs the one before it:

- [x] **Step 1 — Ingestion, normalization, persistence** (this step)
- [ ] Step 2 — Auth + RBAC
- [ ] Step 3 — Correlation engine (upgrade the legacy `/investigate` demo into a real service over persisted events)
- [ ] Step 4 — React dashboard + investigation page
- [ ] Step 5 — Assets, search, incidents workflow, notifications, reports

### What step 1 delivers

A real log ingestion pipeline: raw logs from multiple source formats are
parsed, normalized into one unified event schema, and persisted to
Postgres (or SQLite for local dev without Docker).

```
Raw logs (Windows / syslog / web server / firewall / CloudTrail / generic)
        |
        v
   Parser registry (backend/app/parsers/)
        |
        v
   Normalized Event  {timestamp, host, username, source_ip, event_type, severity, message}
        |
        v
   Postgres (raw_logs + events tables)
        |
        v
   GET /events (search, filter, pagination)
```

Every raw payload is kept in `raw_logs` for audit/replay even if it fails
to parse — nothing is silently dropped.

### Supported log sources

| source_type  | Input format                          |
|--------------|----------------------------------------|
| `windows`    | Windows Security Event Log (JSON)      |
| `syslog`     | Linux syslog lines (SSH, sudo)         |
| `webserver`  | Apache/Nginx combined log format       |
| `firewall`   | Firewall allow/deny log (JSON)         |
| `cloudtrail` | AWS CloudTrail records (JSON)          |
| `generic`    | Already-normalized JSON (REST/CSV/manual upload) |

### API

- `POST /ingest/{source_type}` — body `{"logs": [...]}`, one raw item per source format above
- `POST /ingest/upload?source_type=...` — multipart file upload, CSV or JSON
- `POST /simulate/{scenario}` — ingests a synthetic attack scenario across multiple real log formats so you can try the platform without real infrastructure (currently: `phishing_ransomware`)
- `GET /events?q=&event_type=&severity=&username=&host=&source_ip=&limit=&offset=` — search/filter persisted events
- `POST /investigate` — legacy milestone-1-thin-slice demo (in-memory six-agent pipeline over a fixed sample file); will be replaced by a correlation engine over `/events` in step 3

## Run it

### Option A — Docker Compose (Postgres + Redis + backend)

```bash
docker compose up --build
# API at http://localhost:8000
```

### Option B — local Python, SQLite (no Docker)

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
# API at http://127.0.0.1:8000, data in backend/cybersentinel.db
```

### Try it

```bash
curl -X POST http://localhost:8000/simulate/phishing_ransomware
curl "http://localhost:8000/events?severity=critical"
```

### Tests

```bash
cd backend
python -m pytest
```

## Folder structure

```
backend/
  app/
    agents/       # milestone-1 thin-slice pipeline (pre-DB, still used by /investigate)
    parsers/       # per-source-format normalizers + registry
    db.py          # SQLAlchemy engine/session (Postgres or SQLite)
    db_models.py   # RawLog, Event tables
    ingestion.py   # parse + persist raw logs
    simulate.py    # synthetic attack scenarios for demoing without real infra
    main.py         # FastAPI app
  data/
    samples/        # one raw-format fixture per source type
    sample_logs.json # legacy /investigate fixture
  tests/
docker-compose.yml
```

## Tech stack

Backend: FastAPI, SQLAlchemy, Postgres, Redis (wired up, not yet used), Docker.
Frontend: not built yet (step 4).
