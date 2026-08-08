<div align="center">

# 🛡️ SentraOps

**An AI Security Team for SMEs** — a real Security Operations Center platform with a multi-agent AI analyst layered on top, not a chatbot wrapper around a demo dashboard.

<!--
TODO(demo): record a 2-3 min screen capture: ingest a log source ->
"Simulate attack + correlate" on the Dashboard -> a new incident appears
-> click into it and watch the 6-agent investigation stream live ->
attack graph view -> approve a proposed response action. Save as
docs/demo.gif (or a YouTube/Loom link). Once it exists, replace this
comment with: ![SentraOps demo](docs/demo.gif)
-->
> 🎥 **Demo video/GIF goes here** — ingest → correlate → 6-agent investigation (live) → attack graph → approve a response action.

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

## 🧩 How an incident actually gets investigated

Traced directly from `app/correlation.py` and `app/agents/coordinator.py` — not a marketing diagram:

```text
Raw events (Windows/syslog/firewall/CloudTrail/JSON/CSV), normalized on ingest
        │
        ▼
Correlation engine: union-find clusters events sharing a host, user, or
source IP into one incident candidate — not a fixed rule, a real graph
clustering pass over whatever came in in this batch
        │
        ▼
Risk-scored + a first-pass markdown report written deterministically
(severity weights + threat-intel hit + privilege-escalation/data-transfer
combo) — before any LLM is involved
        │
        ▼
┌─────────────────────────── LangGraph, one incident ───────────────────────────┐
│                                                                                 │
│  Detection ──▶ Investigation ──▶ Threat Intel ──▶ Risk ──▶ Response ──▶ Report │
│                                                                                 │
│  Each node reads everything every prior node wrote via one shared AgentState — │
│  a fixed hand-off order, like a human SOC manager routing one incident through │
│  the team, not six agents debating freely                                     │
└─────────────────────────────────────────────────────────────────────────────┘
        │
        ▼
Institutional memory (similar past incidents, repeat hosts/users, analyst
corrections) and real Neo4j attack-graph connectivity are injected into the
agents above, not just this incident's own events in isolation
        │
        ▼
Streamed live over WebSocket, stage by stage, to the incident view
```

### What each agent actually does

| Agent | Input | Grounded in | Produces |
|---|---|---|---|
| **Detection** | The correlated event cluster + institutional memory | Raw events only — told explicitly not to invent hosts/users/timestamps | Whether this is a genuine coherent attack pattern, its own confidence score, key indicators |
| **Investigation** | Detection's output + full event timeline + Neo4j attack-graph connectivity | The literal timeline, plus only graph nodes actually listed | A chronological forensic narrative, specific findings tied to specific events, the attacker's likely objective |
| **Threat Intel** | Known IOC matches (local table, or live VirusTotal/AbuseIPDB if configured) + timeline | Only matches actually returned — explicitly told it has no live feed access itself | MITRE ATT&CK technique classification **with the specific evidence for each**, malware association if any, its own confidence |
| **Risk** | All prior agents' findings + real asset inventory (criticality/department/owner) + repeat-offender history + graph reach | Asset data and history actually given — never invents a department or asset | A business (not technical) risk score/level and which specific asset is most exposed |
| **Response** | Everything above | The specific hosts/accounts/IPs already found — told not to give generic advice | Concrete containment/eradication/recovery actions, each requiring human approval before anything executes |
| **Report** | The entire investigation | All prior agents' actual output, no templates | Separate executive summary, technical summary, compliance notes, and customer-notification recommendation |

Every agent's system prompt explicitly forbids inventing facts not present in what it was given — the same "compute/correlate first, narrate second" discipline, just applied to a security investigation instead of a stats pipeline.

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
- Breach & Attack Simulation (BAS) — executes real MITRE ATT&CK techniques (14, spanning discovery, collection, credential-access, defense-evasion, and C2) inside a real, disposable Kubernetes pod your own deployment controls, not canned data; real command output flows through the same ingestion/correlation/AI-investigation pipeline as any other source
- **Simulate attack + correlate** (Dashboard) is real-with-fallback: tries a real BAS campaign first when your deployment has cluster access, and only falls back to a canned synthetic scenario when it doesn't — the response always says honestly which one ran, never presents synthetic data as real. Each run assembles a different, believable technique chain (a couple of real discovery techniques plus a random handful of the rest), so it's not the same canned attack on every click

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

## 🧪 Worked example — a real run, not a mockup

Captured directly from the live deployment: register an org, click **Simulate attack + correlate**'s underlying calls one at a time, and let the real 6-agent pipeline investigate whatever the correlation engine actually produced. Nothing below is hand-written.

```text
1. Ingest a phishing/ransomware log scenario (Windows + firewall + syslog, 12 raw events)
   → 5 ingested from Windows, 3 from firewall, 4 from syslog

2. Correlation engine (union-find on shared host/user/IP)
   → 1 incident: "Suspected ransomware / data exfiltration chain"
     confidence 96%, risk 100/100 (critical)
     affected hosts: FINANCE-PC-21, db-server-03
     affected users: admin, j.mehta, svc_update

3. Detection Agent
   → attack_pattern: "credential theft followed by lateral movement
     and potential data exfiltration" (confidence 85%)

4. Investigation Agent
   → attacker_objective: "data exfiltration"
     narrative: failed logins → successful login as j.mehta → firewall
     rule added for 185.220.101.45 → svc_update login → privilege
     escalation → mysqldump of the "customers" database

5. Threat Intel Agent
   → 5 MITRE ATT&CK techniques, each with the specific event as evidence:
     T1078 Valid Accounts, T1068 Privilege Escalation, T1041 Exfiltration
     Over C2 Channel, T1204 User Execution, T1005 Data from Local System

6. Risk Agent
   → business_risk_score: 70/100 (high) — most critical asset: DB-SERVER-03

7. Response Agent
   → urgency: immediate — 6 proposed actions (2 containment, 2 eradication,
     2 recovery), e.g. "Isolate FINANCE-PC-21 and db-server-03 from the
     network", "Block source IP 185.220.101.45 at the firewall/VPN" —
     all pending human approval, none auto-executed

8. Report Agent
   → separate executive summary, technical summary, compliance notes
     (flags potential breach-notification obligations), and a customer-
     notification recommendation
```

The IP `185.220.101.45` and the MITRE technique IDs aren't invented — they come from the scenario's own synthetic log data and the Threat Intel Agent's own classification against real ATT&CK technique definitions, cited against the specific event that triggered each one.

## 📏 Measured, not claimed

Timed directly against the live Render deployment (free tier, shared vCPU):

| Step | Latency | What's actually happening |
|---|---|---|
| Ingest scenario | ~1-15s | Parse + normalize 12 events, embed each one for RAG search, upsert assets |
| Correlate | ~6s | Union-find clustering + threat-intel lookup + deterministic risk scoring + report generation |
| 6-agent investigation | ~15s | Six sequential Groq LLM calls (Detection → Report), each reading everything every prior agent wrote |

Reproduce these yourself: register an org, `POST /simulate/phishing_ransomware`, `POST /correlate`, then `POST /incidents/{id}/investigate` — the numbers above are a single real run, not averaged or cherry-picked.

---

## 🧱 Tech stack

| Layer | Stack |
|---|---|
| Backend | FastAPI, SQLAlchemy, Alembic, Celery + Redis |
| AI / Agents | LangGraph, Groq (`llama-3.3-70b-versatile`), sentence-transformers over ONNX Runtime (local embeddings) |
| Data | PostgreSQL + pgvector, Neo4j |
| Frontend | React, TypeScript, Vite, Tailwind CSS — mobile-first (collapsing sidebar/bottom tab bar, responsive tables, no page ever scrolls horizontally as a whole) |
| Ops | Docker Compose, Kubernetes (Helm + Terraform), Render Blueprint, Prometheus, Grafana / Grafana Cloud |

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

## ☁️ Deploying

Two free ways to put this on a real URL, both actually built and tested against this repo:

**Render (`render.yaml` Blueprint)** — fully managed, no server to maintain. Push to a fork, connect it in Render's dashboard (**New → Blueprint**), and it provisions the backend, Celery worker, static frontend, a standalone embeddings service, and a metrics-forwarding agent from `render.yaml`. Point it at free managed Postgres (e.g. [Neon](https://neon.tech), with `CREATE EXTENSION vector;` for pgvector), [Neo4j AuraDB Free](https://neo4j.com/product/auradb/), and [Upstash Redis](https://upstash.com) instead of the Docker Compose containers. Render's free web service tier caps at 512MB RAM - too tight to run the local embedding model alongside LangGraph/Neo4j/everything else in one process, so `sentraops-embeddings` runs it in its own dedicated free service instead (`embed_text()` calls out to it over HTTP when `EMBEDDINGS_SERVICE_URL` is set, and loads the model in-process otherwise). Metrics forward to [Grafana Cloud](https://grafana.com)'s free tier (`monitoring/prometheus-agent/`) instead of self-hosting Prometheus/Grafana, since Render's free tier has no persistent disk.

A few free-tier gotchas worth knowing before you deploy:
- **Neo4j Aura's database username isn't always `neo4j`** - some instances use the instance ID itself as the username instead. Check the exact value on your instance's Connect / Developer Hub page rather than assuming the classic default.
- **Free web services sleep after 15 minutes idle**, which costs a 30-60s cold start on the next request. A free scheduled ping (hitting `/health` every 10 minutes) keeps a given service warm - but since that uses close to the full 750 free hours/month by itself, only keep-alive the backend, not all five services, or you'll exhaust the shared monthly pool. This repo pings itself via [`.github/workflows/keep-alive.yml`](.github/workflows/keep-alive.yml) (unmetered on a public repo, and a failed run just shows red in the Actions tab instead of silently disabling itself). A third-party pinger like [cron-job.org](https://cron-job.org) works too, but its bot-check heuristics occasionally flag the ping itself as suspicious traffic and auto-disable the whole schedule after a few failures - worth having the Actions workflow as the one that can't quietly stop working unnoticed.
- **Grafana Cloud's dashboard panels don't provision themselves** - connecting the metrics agent only gets data flowing into storage. You still need to manually import `monitoring/grafana/provisioning/dashboards/json/cybersentinel.json` (Grafana Cloud → Dashboards → New → Import) and point each panel at the Prometheus data source Grafana Cloud auto-created for you (not the literal `"Prometheus"` placeholder the JSON ships with).

**Self-hosted + Cloudflare Tunnel** — run `docker compose up` on any machine with a public internet connection (no port-forwarding, no public IP needed) and expose it via a free [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/). No memory ceiling, the complete app with no trade-offs, but tied to that machine staying on. A quick tunnel (`cloudflared tunnel --url ...`) works instantly but gives an ephemeral URL that changes on restart; a named tunnel with your own domain's DNS pointed at Cloudflare's nameservers gives a permanent one.

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

**4. (Optional) Sync ticket resolution back to SentraOps**

By default this integration is one-way: SentraOps → Jira. Resolving the Jira ticket does nothing to the incident on its own. To make completing the ticket automatically close the SentraOps incident it was created for:

- In SentraOps: `GET /connectors/jira/webhook-url` (owner/admin only — call it with your bearer token, e.g. from the browser dev console or `curl`) returns a one-time-generated URL like `https://your-backend.onrender.com/webhooks/jira/{your-org-slug}/{secret}`
- In Jira: **Project settings → Automation → Create rule**
  - Trigger: **Issue transitioned** → select your "Done"/resolved status
  - New action: **Send web request** → paste the URL from above, method `POST`, body `{{issue}}` (Jira's automation web request already sends the issue JSON when left as the default webhook body)
  - Save and enable the rule

The secret is embedded in the URL path itself (same pattern as a Slack/Discord incoming webhook) since Jira Automation's web request action can't send a custom Authorization header on the free/standard plan. Only paste this URL into Jira's own automation config — anyone with it can close incidents in your org. SentraOps matches the incoming Jira issue key against the ticket it created for each approved action, so this only ever closes the incident that ticket was opened for.

---

## 🗂️ Project structure

```
backend/    FastAPI app, agents, migrations, tests
frontend/   React + Vite app
deploy/     Helm chart + Terraform (Kind cluster) for a real K8s deployment
monitoring/ Prometheus + Grafana provisioning, plus a remote-write agent for Grafana Cloud
render.yaml Render Blueprint - backend, Celery worker, static frontend, embeddings service, metrics agent
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
