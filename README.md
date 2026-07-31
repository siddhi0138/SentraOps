<div align="center">

# 🛡️ SentraOps

**An AI Security Team for SMEs** — a real Security Operations Center platform with a multi-agent AI analyst layered on top, not a chatbot wrapper around a demo dashboard.

</div>

---

## 🧭 Why this exists

Most "AI SOC" demos are a dashboard with an LLM bolted on for a chat box. SentraOps is built the other way around: a real, working Security Operations Center — real log ingestion, a real correlation engine, real multi-tenant data isolation — with a genuine multi-agent AI analyst layered on top of that foundation, not in place of it.

Every feature below is backed by a real running system, not a mock:
- A real correlation engine clusters raw events into incidents (union-find over shared host/user/IP), not hardcoded sample incidents
- A real 6-agent [LangGraph](https://github.com/langchain-ai/langgraph) pipeline investigates each incident, with its own conversation log
- A real graph database (Neo4j) backs attack-path and blast-radius analysis
- Real LLM calls (Groq), grounded in your own ingested data via retrieval — the assistant explicitly says so when the evidence doesn't support an answer, rather than inventing one
- Every proposed AI response action requires human approval before anything is treated as "executed" — nothing here is autonomous by default, whether the resulting action is an outbound webhook or a real Jira/ServiceNow ticket

---

## ✨ What it does

**🔎 Core SOC**
- Multi-format log ingestion (Windows Event Log, syslog, firewall, AWS CloudTrail, generic JSON/CSV) with real parsers, normalized into one event schema
- Automatic correlation of raw events into incidents
- Full incident workflow — priority, assignee, comments, status, CSV/report export
- Asset inventory, auto-discovered from ingested logs

**🤖 AI Security Team**
- 6 specialized agents (Detection → Investigation → Threat Intel → Risk → Response → Report) collaborating on one incident
- Real VirusTotal + AbuseIPDB threat-intel lookups when their free-tier API keys are configured, falling back to the platform's own local indicator table (demo seed + synced feeds like URLhaus) when they aren't — same agent logic either way, only the data source changes
- Natural-language chat and search, grounded in your real events via RAG
- Knowledge Base — upload your own playbooks/runbooks/policy docs; chat retrieval searches them alongside events and incidents automatically, with a one-click sample set to try it immediately on a fresh org
- Dual-evidence confidence scoring on every chat answer — cross-checks the RAG retrieval's own semantic-similarity score against whether the same entities are actually connected in the real Neo4j attack graph, instead of trusting either signal alone
- Institutional memory: repeat hosts/users and similar past incidents feed into agent reasoning, not just the current incident in isolation
- Live streaming investigation status over WebSockets
- Learning loop — analyst feedback (accurate / false positive / missed) on past AI investigations, tracked as a real accuracy record over time

**🕸️ Graph & Simulation**
- Neo4j-backed attack graph — see how hosts/users/IPs connect across *every* incident, not just one at a time
- Digital Twin — "what happens if this is compromised?" blast-radius simulation with an AI-narrated lateral-movement story
- Attack Replay — step through a real incident's timeline chronologically, then through the AI's own investigation stages
- Breach & Attack Simulation (BAS) — executes real MITRE ATT&CK techniques (discovery, defense-evasion, C2) inside a real, disposable Kubernetes pod your own deployment controls, not canned data; real command output flows through the same ingestion/correlation/AI-investigation pipeline as any other source
- **Simulate attack + correlate** (Dashboard) is real-with-fallback: tries a real BAS campaign first when your deployment has cluster access, and only falls back to a canned synthetic scenario when it doesn't — the response always says honestly which one ran, never presents synthetic data as real

**💬 Slack Integration**
- Real OAuth "Connect to Slack" install — one registered app, independently installable into any organization's own workspace, multi-tenant by design
- New-incident alerts, live per-agent investigation progress, and Approve/Reject buttons for proposed actions, posted straight into the workspace (via the incoming-webhook the OAuth grant returns, not a bot that has to be manually invited into a channel)
- Slash commands: `/sentraops status | incidents | summary | ask <question> | hunt <topic> | investigate <id>`
- Optional routing of critical-severity incidents to a second, dedicated channel
- Daily AI-generated executive summary, posted automatically (Celery Beat)

**🏢 Enterprise**
- Multi-tenant organizations with real data isolation, verified with dedicated cross-tenant tests
- Pluggable connector framework (real free-tier feeds: URLhaus, GitHub Security Advisories, plus a config-driven Generic REST connector for any vendor's own API) and response actions — outbound webhooks (Slack/Discord/generic), plus real Jira and ServiceNow ticket creation for an approved response action, with Jira tickets auto-assigned to the incident's SentraOps assignee when their email matches a real Jira user
- Compliance mapping (NIST / MITRE / CIS / PCI-DSS) against your real ingested data
- Executive dashboard with AI-generated briefings
- Predictive anomaly detection over real host/user behavior
- SOC Command Center — a unified live queue of incidents and pending approvals
- Playbook marketplace, API keys, audit log
- RBAC with six real SOC roles - Owner and Admin (full org/integration config; only an Owner can grant/revoke Owner itself), SOC Manager and Analyst (investigate, chat, approve actions), Executive and Auditor (read-only everywhere)
- Team management (Settings → Admin) — every role can see who's on the team, Owners/Admins can change anyone's role in one click
- Guided in-app product tour for first-time users

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

On first open, register a new organization from the login screen, then click **Simulate attack + correlate** on the Dashboard. That one click ingests an attack scenario through the real correlation engine, runs a full AI investigation on the resulting incident, and syncs the attack graph — so the whole platform is populated with real data end to end, on any account, not just a pre-seeded demo one. Under `docker compose` this uses a canned synthetic scenario (no Kubernetes API available); deployed to a real cluster (see `deploy/helm/`), the same button runs a real BAS campaign instead — see Breach & Attack Simulation above.

### Key environment variables

| Variable | Required | Notes |
|---|---|---|
| `GROQ_API_KEY` | For AI features | Free tier at console.groq.com. The rest of the app works without it. |
| `JWT_SECRET_KEY` | For production | Generate with `python -c "import secrets; print(secrets.token_hex(32))"` |
| `DATABASE_URL` | No | Defaults to the Postgres container in `docker-compose.yml` |
| `SLACK_CLIENT_ID` / `SLACK_CLIENT_SECRET` / `SLACK_SIGNING_SECRET` | For Slack integration | From your own Slack app at api.slack.com/apps. The rest of the app works without it — "Connect to Slack" just won't appear functional until set. |
| `FRONTEND_URL` | For Slack integration | Where Slack redirects/links back to after an OAuth install (e.g. `http://localhost:5173`) |
| `VIRUSTOTAL_API_KEY` / `ABUSEIPDB_API_KEY` | No | Free tiers at virustotal.com / abuseipdb.com. Without them, the Threat Intel agent uses the platform's own local indicator table instead of live lookups. |

---

## 🔌 Connecting Slack & Jira

Both are optional — the app works fine without either. Here's how to turn them on, in plain steps.

### Slack

SentraOps can post straight into a Slack channel — new incident alerts, live investigation progress, and Approve/Reject buttons you can click right from Slack.

**1. Create the Slack app**
- Go to [api.slack.com/apps](https://api.slack.com/apps) → **Create New App** → **From an app manifest**
- Pick the workspace you want to use
- Paste this manifest (swap the URLs if your backend isn't on `localhost:8000`):

```yaml
display_information:
  name: SentraOps
oauth_config:
  redirect_urls:
    - http://localhost:8000/connectors/slack/callback
  scopes:
    bot:
      - chat:write
      - chat:write.public
      - commands
      - channels:read
      - incoming-webhook
features:
  bot_user:
    display_name: SentraOps
  slash_commands:
    - command: /sentraops
      url: http://localhost:8000/slack/commands
      description: Check status, list incidents, or investigate one
settings:
  interactivity:
    is_enabled: true
    request_url: http://localhost:8000/slack/interactions
```
- Click **Create**

**2. Copy your credentials**
- On the app's **Basic Information** page, copy the **Client ID**, **Client Secret**, and **Signing Secret**
- Put them in your `.env` file (`SLACK_CLIENT_ID`, `SLACK_CLIENT_SECRET`, `SLACK_SIGNING_SECRET`), then restart the app

**3. Make Slack able to reach your machine**
Slack's servers need to send slash commands and button clicks to a real, public URL — `localhost` doesn't work for that part. If you're just running this locally, use a free tunnel like [ngrok](https://ngrok.com):
```bash
ngrok http 8000
```
Take the `https://...ngrok-free.app` URL it gives you, and update the **Slash Commands** and **Interactivity** URLs in your Slack app's settings to use it instead of `localhost`. (The OAuth redirect URL can stay as `localhost` — that one only runs in your own browser, not from Slack's side.)

**4. Connect it**
- In SentraOps: **Settings → Integrations**, pick **Slack**, click **Connect to Slack**
- Approve it on Slack's screen and choose a channel — done. Alerts will start appearing there.

### Jira

SentraOps can open a real Jira ticket automatically whenever a proposed response action gets approved.

**1. Get a free Jira account** (skip if you already have one)
- Sign up at [atlassian.com/software/jira/free](https://www.atlassian.com/software/jira/free) — no credit card needed
- Create a project (Kanban template is easiest) and note its **project key** — shown near the project name, e.g. `SCRUM`

**2. Create an API token**
- Go to [id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens) → **Create API token** → copy it (it's only shown once)

**3. Add it in SentraOps**
- **Settings → Integrations → Response Action Integrations**, pick **Jira**, fill in:

| Field | What to put |
|---|---|
| `base_url` | Your Jira site, e.g. `https://yourname.atlassian.net` |
| `email` | The email you signed up with |
| `api_token` | From step 2 |
| `project_key` | From step 1 |

- Click **Add Integration** — no restart needed, this one's entirely set up through the UI.

Approve any proposed action afterward and a real ticket shows up in your Jira project.

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
