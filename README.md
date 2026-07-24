# CyberSentinel AI

An AI Security Team for SMEs, built the way a real product would be: a
solid SOC platform first, AI reasoning layered on top of it later.

## Roadmap

```
Milestone 1: CyberSentinel Core       - Foundation SOC (no AI)          [DONE]
Milestone 2: AI Security Analyst      - LLM reasoning over the platform  [IN PROGRESS]
Milestone 3: Autonomous AI Security Team - Multi-agent investigation
Milestone 4: Enterprise SOC Platform  - Streaming, graph, RBAC, deployment
```

## Milestone 1: CyberSentinel Core — complete

Built in dependency order, since each layer needed the one before it:

- [x] Step 1 — Ingestion, normalization, persistence
- [x] Step 2 — Auth + RBAC
- [x] Step 3 — Correlation engine
- [x] Step 4 — React dashboard + investigation page
- [x] Step 5 — Assets, search, incident workflow, notifications, reports

### Database migrations

Schema changes go through Alembic (`backend/alembic/`), not
`create_all()` — the app's startup (`init_db()`) runs `alembic upgrade head`
against `DATABASE_URL`. To add a schema change: edit `db_models.py`, then
`cd backend && alembic revision --autogenerate -m "..."` and review the
generated file before committing (SQLite can't reflect expression-based
indexes, so those need adding by hand — see the second migration for an
example). Tests run migrations too (against their own per-test SQLite
file), so drift between `db_models.py` and the migration files fails the
test suite instead of silently working via `create_all()`.

### Concurrency

- **Correlation is safe under concurrent `/correlate` calls.** Candidate
  events are atomically claimed via a single bulk `UPDATE` before any
  processing; a second concurrent call's identical claim can't see rows
  already claimed. Nothing commits until the very end, so a crash mid-run
  releases the claim instead of leaking it. See `run_correlation` in
  `correlation.py` and `tests/test_correlation_concurrency.py`.
- **Asset upsert is safe under concurrent first-sightings of a new host.**
  A case-insensitive unique index (`ix_assets_host_lower`) enforces
  uniqueness at the database level; a losing insert recovers via a
  SAVEPOINT + fallback update rather than crashing or duplicating. See
  `_upsert_asset` in `ingestion.py` and `tests/test_asset_concurrency.py`.

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

### What step 5 delivers

The remaining Milestone 1 modules, closing it out as a complete product:

- **Assets** — every host seen in ingested events is auto-upserted into an
  asset inventory (first/last seen, event count), case-insensitively so the
  same host logged with different casing across sources still merges into
  one row. Admin/analyst can enrich it with OS, department, owner, and a
  criticality rating.
- **Global search** — `GET /search?q=` fans a query out across events,
  incidents (by title), and assets in one call; the navbar search box shows
  grouped, clickable results.
- **Incident workflow** — incidents now have a `priority` (defaults from
  risk level, editable) and an `assignee` (any admin/analyst, via a picker
  backed by `GET /users`), plus a threaded comments log
  (`POST /incidents/{id}/comments`).
- **Notifications** — every new incident notifies all admins/analysts;
  assigning an incident notifies the assignee. In-app only for now (no
  email/Slack yet — see the roadmap). The navbar bell polls
  `GET /notifications` every 30s for an unread badge.
- **Reports/export** — `GET /incidents/{id}/report.md` downloads the
  existing markdown report; `GET /events/export.csv` and
  `GET /incidents/export.csv` export the current filtered view. PDF export
  was deliberately left out of this milestone — it needs a real rendering
  dependency (WeasyPrint/reportlab) that isn't worth pulling in before
  there's a design worth exporting to PDF.

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
- `GET /incidents/{id}` — full incident detail: timeline, alerts, threat intel, risk factors, recommended actions, markdown report, comments. **Requires any authenticated role.**
- `GET /incidents/{id}/report.md` — download the markdown report. **Requires any authenticated role.**
- `GET /incidents/export.csv`, `GET /events/export.csv` — CSV export (same filters as the list endpoints). **Requires any authenticated role.**
- `PATCH /incidents/{id}` — body `{"status"?, "priority"?, "assignee_id"?}` (any subset). Assigning notifies the assignee. **Requires admin or analyst role.**
- `POST /incidents/{id}/comments` — body `{"body"}`. **Requires admin or analyst role.**
- `GET /assets?q=&limit=&offset=` — list auto-discovered assets. **Requires any authenticated role.**
- `PATCH /assets/{id}` — body `{"os"?, "department"?, "owner"?, "criticality"?}`. **Requires admin or analyst role.**
- `GET /search?q=` — events + incidents + assets matching `q`, ≤10 each. **Requires any authenticated role.**
- `GET /stats` — dashboard aggregates (event/incident counts, severity distribution, 5 most recent incidents), computed via SQL over the whole table, not a capped sample. **Requires any authenticated role.**
- `GET /notifications?unread_only=` — the current user's notifications + unread count.
- `PATCH /notifications/{id}/read`, `POST /notifications/read-all` — mark read.

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
- `GET /users` — list all users (used to populate the incident-assignee picker). **Admin or analyst.**
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

## Milestone 2: AI Security Analyst — in progress

One AI analyst (not a multi-agent swarm — that's Milestone 3), grounded in
this platform's own data via RAG instead of hallucinating.

**LLM: Groq** (free tier — `llama-3.3-70b-versatile` by default, override via
`GROQ_MODEL`), not the GPT-5.x/Gemini the original spec named — swapped for
cost. **Embeddings: local, not an API** — `sentence-transformers`
(`all-MiniLM-L6-v2`, 384-dim) runs on CPU, free, no key needed; only the
final answer-generation step calls Groq. **Vector store: pgvector**, not a
separate Qdrant container — one less service to run, lives in the Postgres
you already have.

- [x] **Step 1 — pgvector + local embeddings pipeline.** Every ingested
  event and every correlated incident gets embedded automatically
  (`app/embeddings.py`, `app/rag.py`). Dialect-aware: real indexed
  `cosine_distance()` search on Postgres, brute-force Python cosine
  similarity on SQLite (dev only, not meant to scale). Requires a real
  Postgres container to test properly — the SQLite fallback path can't
  catch bugs in the pgvector-specific code (and didn't: see below).
- [x] **Step 2 — RAG retrieval endpoint** (`GET /rag/search?q=&content_type=`)
  — semantic search over that index, no LLM call yet. This is the
  retrieval half of RAG; step 3 is retrieval + generation.
- [x] **Step 3 — AI chat** (`POST /chat`, "AI Analyst" page). Retrieves
  evidence via the same `app/rag.py` search, then a Groq call grounded in
  it — instructed to cite specific hosts/users/timestamps/incident numbers
  from the evidence and to say so plainly rather than guess when the
  evidence doesn't support an answer. No conversation memory yet (each
  question is answered independently); that's a reasonable v2, not
  required for a working analyst chat.
- [ ] Step 4 — Incident explanation, timeline narration, threat summary
- [ ] Step 5 — Log explanation, NL→query generator, similar-incident
  search, threat knowledge Q&A, executive/analyst report modes,
  confidence/explainability display

**Setup:** get a free key at console.groq.com → API Keys, then set
`GROQ_API_KEY` in `.env` (repo root, for Docker) and `backend/.env` (for
local `uvicorn`, loaded via `python-dotenv`) — see `.env.example`. Postgres
must be the `pgvector/pgvector:pg16` image (already the default in
`docker-compose.yml`); a plain `postgres` image doesn't have the
`vector` extension available for the migration to enable.

**Real bugs these steps caught:**
- `Embedding.vector.cosine_distance(...)` raised `AttributeError` the first
  time it ran against real Postgres, because wrapping
  `pgvector.sqlalchemy.Vector` in a `TypeDecorator` (needed for the SQLite
  fallback) doesn't automatically forward the wrapped type's special
  comparator methods — needs `comparator_factory = Vector.comparator_factory`
  set explicitly. All prior testing had only exercised the SQLite path,
  which never calls that method at all. Lesson: dialect-specific code needs
  a dialect-specific test, full stop — a passing SQLite test proves nothing
  about the Postgres path when the two paths use genuinely different code.
- `backend/.env` (holding the real Groq key) had no `.dockerignore` entry,
  so `COPY . .` baked the live key straight into the built Docker image —
  confirmed via `docker run ... cat /app/.env`, then fixed with
  `backend/.dockerignore` and a clean rebuild. Whenever a new `.env` file
  shows up anywhere in this repo, check the nearest Dockerfile's
  `COPY`/`.dockerignore` pairing immediately.

**Chat endpoint:**
- `POST /chat` — body `{"question"}` → `{question, answer, sources}`.
  `sources` is the same shape `/rag/search` returns, so the UI can link
  straight back to the incidents/events that grounded the answer. Returns
  `503` if `GROQ_API_KEY` isn't set, `502` if Groq itself fails (rate
  limit, timeout, ...). **Requires any authenticated role.**

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
    db.py           # SQLAlchemy engine/session (Postgres or SQLite), .env loading
    db_models.py    # RawLog, Event, User, Incident, IncidentComment, Asset, Notification, Embedding tables
    auth.py         # password hashing, JWT, RBAC dependencies
    ingestion.py    # parse + persist raw logs, upsert asset inventory, embed events
    correlation.py  # cluster events into incidents, score risk, recommend actions, notify, embed incidents
    embeddings.py   # local sentence-transformers wrapper (free, no API key)
    rag.py          # store/search embeddings (pgvector on Postgres, brute-force on SQLite)
    ai.py           # Groq client + system prompt - the "generation" half of RAG
    simulate.py     # synthetic attack scenarios for demoing without real infra
    main.py         # FastAPI app
  alembic/          # migrations - see "Database migrations" above
  data/
    samples/        # one raw-format fixture per source type
  tests/
frontend/
  src/
    api/            # fetch client (JWT storage + refresh-on-401) + TS types
    auth/           # AuthContext (login/register/logout, session restore)
    components/     # Layout, ProtectedRoute, badges, stat cards, SearchBar, NotificationBell
    pages/          # Login, Register, Dashboard, Events, Incidents(+ detail), Assets, AIAnalyst
docker-compose.yml
```

## Tech stack

Backend: FastAPI, SQLAlchemy, Alembic, Postgres + pgvector, Redis (wired up, not yet used), Docker.
AI: Groq (`llama-3.3-70b-versatile`, free tier) for generation, local `sentence-transformers` for embeddings — no paid API required for any of it.
Frontend: React, TypeScript, Tailwind CSS v4 (+ typography plugin), React Router, Recharts, react-markdown, Vite, nginx (prod image).
