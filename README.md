<div align="center">

# 🛡️ SentraOps

**An AI Security Team for SMEs** — a real Security Operations Center platform with a multi-agent AI analyst layered on top, not a chatbot wrapper around a demo dashboard.

[![CI](https://github.com/siddhi0138/SentraOps/actions/workflows/ci.yml/badge.svg)](https://github.com/siddhi0138/SentraOps/actions/workflows/ci.yml)

</div>

---

## 🧭 Why this exists

Most "AI SOC" demos are a dashboard with an LLM bolted on for a chat box. SentraOps is built the other way around: a real, working Security Operations Center — real log ingestion, a real correlation engine, real multi-tenant data isolation — with a genuine multi-agent AI analyst layered on top of that foundation, not in place of it.

Every feature below is backed by a real running system, not a mock:
- A real correlation engine clusters raw events into incidents (union-find over shared host/user/IP), not hardcoded sample incidents
- A real 6-agent [LangGraph](https://github.com/langchain-ai/langgraph) pipeline investigates each incident, with its own conversation log
- A real graph database (Neo4j) backs attack-path and blast-radius analysis
- Real LLM calls (Groq), grounded in your own ingested data via retrieval — the assistant explicitly says so when the evidence doesn't support an answer, rather than inventing one
- Every proposed AI response action requires human approval before anything is treated as "executed" — nothing here is autonomous by default

---

## ✨ What it does

**🔎 Core SOC**
- Multi-format log ingestion (Windows Event Log, syslog, firewall, AWS CloudTrail, generic JSON/CSV) with real parsers, normalized into one event schema
- Automatic correlation of raw events into incidents
- Full incident workflow — priority, assignee, comments, status, CSV/report export
- Asset inventory, auto-discovered from ingested logs

**🤖 AI Security Team**
- 6 specialized agents (Detection → Investigation → Threat Intel → Risk → Response → Report) collaborating on one incident
- Natural-language chat and search, grounded in your real events via RAG
- Institutional memory: repeat hosts/users and similar past incidents feed into agent reasoning, not just the current incident in isolation
- Live streaming investigation status over WebSockets
- Learning loop — analyst feedback (accurate / false positive / missed) on past AI investigations, tracked as a real accuracy record over time

**🕸️ Graph & Simulation**
- Neo4j-backed attack graph — see how hosts/users/IPs connect across *every* incident, not just one at a time
- Digital Twin — "what happens if this is compromised?" blast-radius simulation with an AI-narrated lateral-movement story
- Attack Replay — step through a real incident's timeline chronologically, then through the AI's own investigation stages

**🏢 Enterprise**
- Multi-tenant organizations with real data isolation, verified with dedicated cross-tenant tests
- Pluggable connector framework (real free-tier feeds: URLhaus, GitHub Security Advisories) and response-action webhooks
- Compliance mapping (NIST / MITRE / CIS / PCI-DSS) against your real ingested data
- Executive dashboard with AI-generated briefings
- Predictive anomaly detection over real host/user behavior
- SOC Command Center — a unified live queue of incidents and pending approvals
- Playbook marketplace, RBAC, API keys, audit log

**📊 Observability**
- Prometheus + Grafana out of the box, with app-specific metrics (investigation duration, AI call cost/latency, success rate) — not just generic HTTP metrics

---

## 🧱 Tech stack

| Layer | Stack |
|---|---|
| Backend | FastAPI, SQLAlchemy, Alembic, Celery + Redis |
| AI / Agents | LangGraph, Groq (`llama-3.3-70b-versatile`), sentence-transformers (local embeddings) |
| Data | PostgreSQL + pgvector, Neo4j |
| Frontend | React, TypeScript, Vite, Tailwind CSS |
| Ops | Docker Compose, Kubernetes (Helm + Terraform), Prometheus, Grafana |

No paid API keys required to run the core platform — the LLM layer uses Groq's free tier, embeddings run locally (no API key at all), and the two reference connectors are free/keyless.

---

## 🚀 Quick start

**Prerequisites:** Docker and Docker Compose. Nothing else — Postgres, Redis, and Neo4j all run as containers.

```bash
git clone https://github.com/siddhi0138/SentraOps.git
cd SentraOps
cp .env.example .env        # add a free Groq API key (console.groq.com) to enable AI features
docker compose up --build
```

| Service | URL |
|---|---|
| Frontend | [http://localhost:5173](http://localhost:5173) |
| Backend API docs (Swagger) | [http://localhost:8000/docs](http://localhost:8000/docs) |
| Grafana | [http://localhost:3001](http://localhost:3001) (`admin` / `admin`) |
| Prometheus | [http://localhost:9090](http://localhost:9090) |

First launch downloads the local embedding model, so the first AI-touching request may take a couple of minutes — everything after that is fast.

On first open, register a new organization from the login screen, then click **Simulate attack + correlate** on the Dashboard. That one click ingests a real synthetic attack scenario through the real correlation engine, runs a full AI investigation on the resulting incident, and syncs the attack graph — so the whole platform is populated with real (if synthetic) data end to end, on any account, not just a pre-seeded demo one.

### Key environment variables

| Variable | Required | Notes |
|---|---|---|
| `GROQ_API_KEY` | For AI features | Free tier at console.groq.com. The rest of the app works without it. |
| `JWT_SECRET_KEY` | For production | Generate with `python -c "import secrets; print(secrets.token_hex(32))"` |
| `DATABASE_URL` | No | Defaults to the Postgres container in `docker-compose.yml` |

---

## 🗂️ Project structure

```
backend/    FastAPI app, agents, migrations, tests
frontend/   React + Vite app
deploy/     Helm chart + Terraform (Kind cluster) for a real K8s deployment
monitoring/ Prometheus + Grafana provisioning
```

## 🧪 Tests

```bash
cd backend && pytest
```

```bash
cd frontend && npm run build   # typecheck + production build
```

CI runs both on every push/PR via GitHub Actions (`.github/workflows/ci.yml`).

---

## 🤝 Contributing

This started as a solo portfolio project, but issues and PRs are welcome.

- **Bug reports / feature ideas:** open an issue with what you expected vs. what happened.
- **Pull requests:** keep them focused — one change per PR is easier to review than a bundle of unrelated ones. Make sure `pytest` (backend) and `npm run build` (frontend) both pass before opening.
- **Code style:** no linter-enforced style beyond what's already in the repo (ESLint for the frontend, plain PEP 8-ish for the backend) — match the surrounding code.
- Real verification matters more than test coverage numbers here — if you're adding a feature that touches the AI agents, the graph, or anything dialect-sensitive (SQLite vs. Postgres), a live check against the real service is worth more than a mocked test that can't catch what the mock doesn't model.

---

<div align="center">

Built as a portfolio project demonstrating agentic AI orchestration, multi-tenant SaaS architecture, graph analytics, and full-stack systems design — not a CRUD dashboard with an AI label on it.

</div>
