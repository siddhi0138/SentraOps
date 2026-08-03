# 🛡️ CyberSentinel AI

**An AI Security Team for SMEs** — a real Security Operations Center platform with a multi-agent AI analyst layered on top, not a chatbot wrapper around a demo dashboard.

Every feature in this repo is backed by a real running system: a genuine correlation engine, a real 6-agent LangGraph investigation pipeline, a real graph database for attack-path analysis, and real LLM calls (Groq) grounded in your own ingested data — not mocked responses or canned demo content.

---

## ✨ What it does

**🔎 Core SOC**
- Multi-format log ingestion (Windows Event Log, syslog, firewall, AWS CloudTrail, generic JSON/CSV) with real parsers
- Automatic correlation of raw events into incidents (union-find over shared host/user/IP)
- Full incident workflow — priority, assignee, comments, status, CSV/report export
- Asset inventory, auto-discovered from ingested logs

**🤖 AI Security Team**
- 6 specialized agents (Detection → Investigation → Threat Intel → Risk → Response → Report) collaborating on one incident via LangGraph
- Every proposed response action requires human approval before anything "executes" — nothing is autonomous by default
- Natural-language chat and search, grounded in your real events via RAG (no hallucinated answers — it says so when it can't answer)
- Institutional memory: repeat hosts/users and similar past incidents feed into agent reasoning
- Live streaming investigation status over WebSockets

**🕸️ Graph & Simulation**
- Neo4j-backed attack graph — see how hosts/users/IPs connect across incidents
- Digital Twin — "what happens if this is compromised?" blast-radius simulation with an AI-narrated lateral-movement story
- Attack Replay — step through a real incident's timeline chronologically

**🏢 Enterprise**
- Multi-tenant organizations with real data isolation (verified with dedicated cross-tenant tests, not just assumed)
- Pluggable connector framework (real free-tier feeds: URLhaus, GitHub Security Advisories) and response-action webhooks
- Compliance mapping (NIST / MITRE / CIS / PCI-DSS) against your real ingested data
- Executive dashboard with AI-generated briefings
- Predictive anomaly detection over real host/user behavior
- Learning loop — analyst feedback on past AI investigations, tracked as a real accuracy record
- SOC Command Center — unified live queue of incidents + pending approvals
- Playbook marketplace, RBAC, API keys, audit log

**📊 Observability**
- Prometheus + Grafana out of the box, with app-specific metrics (investigation duration, success rate)

---

## 🧱 Tech stack

| Layer | Stack |
|---|---|
| Backend | FastAPI, SQLAlchemy, Alembic, Celery + Redis |
| AI / Agents | LangGraph, Groq (`llama-3.3-70b-versatile`), sentence-transformers (local embeddings) |
| Data | PostgreSQL + pgvector, Neo4j |
| Frontend | React, TypeScript, Vite, Tailwind CSS |
| Ops | Docker Compose, Kubernetes (Helm + Terraform), Prometheus, Grafana |

No paid API keys required to run the core platform — the LLM layer uses Groq's free tier, embeddings run locally, and the two reference connectors are free/keyless.

---

## 🚀 Quick start

```bash
git clone https://github.com/siddhi0138/SentraOps.git
cd SentraOps
cp .env.example .env        # add a free Groq API key (groq.com) to enable AI features
docker compose up --build
```

- Frontend: [http://localhost:5173](http://localhost:5173)
- Backend API docs: [http://localhost:8000/docs](http://localhost:8000/docs)
- Grafana: [http://localhost:3001](http://localhost:3001) (admin/admin)

First launch downloads the local embedding model, so the first AI-touching request may take a couple of minutes — everything after that is fast.

On first open, register a new organization from the login screen, then click **Simulate attack + correlate** on the Dashboard to generate a real incident, run the AI Security Team on it, and see the whole platform populated end to end.

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

---

Built as a portfolio project demonstrating agentic AI orchestration, multi-tenant SaaS architecture, graph analytics, and full-stack systems design — not a CRUD dashboard with an AI label on it.
