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

- [x] Step 1 — Ingestion, normalization, persistence
- [x] Step 2 — Auth + RBAC
- [x] Step 3 — Correlation engine
- [x] **Step 4 — React dashboard + investigation page** (this step)
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

### What step 3 delivers

The correlation engine (`backend/app/correlation.py`) turns a pile of
individually-normalized events into incidents an analyst can actually act
on, instead of dozens of disconnected alerts:

```
Uncorrelated events (severity medium/high/critical = "alerts")
        |
        v
   Cluster alerts into connected components
   (shared username / host / source IP, case-insensitive)
        |
        v
   Per cluster: pull in the full timeline (all severities, same identity)
        |
        v
   Classify (ransomware/exfil vs privilege escalation vs suspicious)
   + mock threat-intel lookup + risk scoring + response recommendations
   + markdown incident report
        |
        v
   Incident row (events.incident_id backfilled) -> GET /incidents
```

Re-running `/correlate` only looks at events not yet attached to an
incident, so it's safe to call repeatedly as new logs arrive.

### What step 4 delivers

A React + TypeScript + Tailwind dashboard (`frontend/`) over the API above:

- **Login/Register** — JWT stored client-side, access token auto-refreshed on 401.
- **Dashboard** — stat cards (total events, open/critical incidents), a severity
  distribution chart, recent incidents, and a "Simulate attack + correlate"
  button (admin/analyst only) to generate demo data with one click.
- **Events** — searchable, filterable, paginated table over `/events`.
- **Incidents** — list + detail view: timeline, alerts, threat intel, risk
  factors, recommended actions, the full markdown report, and an open/close
  status toggle (admin/analyst only).

Role is enforced server-side regardless of what the UI shows/hides — the
frontend just reflects it so a viewer doesn't see action buttons that would
403 anyway.

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

- `POST /ingest/{source_type}` — body `{"logs": [...]}`, one raw item per source format above. **Requires admin or analyst role.**
- `POST /ingest/upload?source_type=...` — multipart file upload, CSV or JSON. **Requires admin or analyst role.**
- `POST /simulate/{scenario}` — ingests a synthetic attack scenario across multiple real log formats so you can try the platform without real infrastructure (currently: `phishing_ransomware`). **Requires admin or analyst role.**
- `GET /events?q=&event_type=&severity=&username=&host=&source_ip=&limit=&offset=` — search/filter persisted events. **Requires any authenticated role.**
- `POST /correlate` — clusters not-yet-correlated events into incidents. **Requires admin or analyst role.**
- `GET /incidents?status=&risk_level=&limit=&offset=` — list incidents. **Requires any authenticated role.**
- `GET /incidents/{id}` — full incident detail: timeline, alerts, threat intel, risk factors, recommended actions, markdown report. **Requires any authenticated role.**
- `PATCH /incidents/{id}?status=open|closed` — update incident status. **Requires admin or analyst role.**

### Auth + RBAC

Three roles: `admin`, `analyst`, `viewer`. The first account ever registered
is auto-promoted to admin (so there's always someone who can manage the
rest); every later signup defaults to `viewer` until an admin raises their
role. Roles are looked up fresh from the DB on every request, so a promoted
user's existing access token works immediately without re-authenticating.

- `POST /auth/register` — body `{"email", "password"}`
- `POST /auth/login` — body `{"email", "password"}` → `{access_token, refresh_token}`
- `POST /auth/refresh` — body `{"refresh_token"}` → new token pair
- `GET /auth/me` — current user (any authenticated role)
- `GET /users` — list all users. **Admin only.**
- `PATCH /users/{id}/role` — body `{"role": "admin"|"analyst"|"viewer"}`. **Admin only.**

Authenticated requests send `Authorization: Bearer <access_token>`.

```bash
curl -X POST localhost:8000/auth/register -d '{"email":"you@corp.com","password":"..."}' -H "Content-Type: application/json"
TOKEN=$(curl -X POST localhost:8000/auth/login -d '{"email":"you@corp.com","password":"..."}' -H "Content-Type: application/json" | jq -r .access_token)
curl -X POST localhost:8000/simulate/phishing_ransomware -H "Authorization: Bearer $TOKEN"
```

Set `JWT_SECRET_KEY` to a real secret in any non-local environment (see
`.env.example` for how to generate one) — the default is dev-only and
publicly known.

## Run it

### Option A — Docker Compose (Postgres + Redis + backend + frontend)

```bash
docker compose up --build
# Backend API at http://localhost:8000
# Frontend at   http://localhost:5173
```

### Option B — local dev (no Docker)

```bash
# backend, in one terminal
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
# API at http://127.0.0.1:8000, data in backend/cybersentinel.db

# frontend, in another terminal
cd frontend
npm install
npm run dev
# UI at http://localhost:5173, proxies /api/* to the backend (see vite.config.ts)
```

Open the UI, register (the first account becomes admin), then click
"Simulate attack + correlate" on the dashboard to generate demo data.

### Try the API directly

```bash
curl -X POST localhost:8000/auth/register -H "Content-Type: application/json" -d '{"email":"you@corp.com","password":"Secret123!"}'
TOKEN=$(curl -s -X POST localhost:8000/auth/login -H "Content-Type: application/json" -d '{"email":"you@corp.com","password":"Secret123!"}' | python -c "import json,sys;print(json.load(sys.stdin)['access_token'])")
curl -X POST localhost:8000/simulate/phishing_ransomware -H "Authorization: Bearer $TOKEN"
curl -X POST localhost:8000/correlate -H "Authorization: Bearer $TOKEN"
curl localhost:8000/incidents -H "Authorization: Bearer $TOKEN"
```

### Tests

```bash
cd backend
python -m pytest

cd frontend
npm run build   # typechecks (tsc) + bundles
```

## Folder structure

```
backend/
  app/
    parsers/        # per-source-format normalizers + registry
    db.py           # SQLAlchemy engine/session (Postgres or SQLite)
    db_models.py    # RawLog, Event, User, Incident tables
    auth.py         # password hashing, JWT, RBAC dependencies
    ingestion.py    # parse + persist raw logs
    correlation.py  # cluster events into incidents, score risk, recommend actions
    simulate.py     # synthetic attack scenarios for demoing without real infra
    main.py         # FastAPI app
  data/
    samples/        # one raw-format fixture per source type
  tests/
frontend/
  src/
    api/            # fetch client (JWT storage + refresh-on-401) + TS types
    auth/           # AuthContext (login/register/logout, session restore)
    components/     # Layout, ProtectedRoute, badges, stat cards
    pages/          # Login, Register, Dashboard, Events, Incidents(+ detail)
docker-compose.yml
```

## Tech stack

Backend: FastAPI, SQLAlchemy, Postgres, Redis (wired up, not yet used), Docker.
Frontend: React, TypeScript, Tailwind CSS v4, React Router, Recharts, Vite, nginx (prod image).
