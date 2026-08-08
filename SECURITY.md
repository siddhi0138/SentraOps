# Security

How SentraOps handles auth, secrets, and abuse prevention — and where it deliberately draws the line, given this is a portfolio project rather than a paid product with a security team behind it.

## Authentication

- Passwords are hashed with **bcrypt** (`app/auth.py`), never stored or logged in plaintext.
- Sessions are short-lived **JWTs**: a 30-minute access token plus a 7-day refresh token (`app/auth.py`). `JWT_SECRET_KEY` must be set to a real random value in production (`python -c "import secrets; print(secrets.token_hex(32))"`) — the code ships with an obviously-fake dev default so a forgotten env var fails loudly, not silently.
- Machine-to-machine access uses **API keys**, hashed with SHA-256 before storage (`app/admin.py`) — a fast, deterministic hash is correct here since a generated API key is high-entropy and doesn't need bcrypt's deliberate slowness against offline guessing the way a human password does.
- The frontend stores both tokens in `localStorage` (`frontend/src/api/client.ts`), not an httpOnly cookie — a deliberate tradeoff common to token-based SPA/API pairs (no CSRF handling needed), but it does mean a successful XSS on the frontend could read them. The short 30-minute access-token lifetime bounds how long a stolen one stays useful.

## Authorization (RBAC)

Six roles (`owner`, `admin`, `soc_manager`, `analyst`, `executive`, `auditor`) are enforced **server-side** via a `require_roles(...)` FastAPI dependency (`app/auth.py`), not just hidden in the frontend UI. Every mutating or sensitive endpoint — user role changes, API key issuance/revocation, connector credentials, incident status changes, running a BAS campaign — has an explicit role check that raises a real 403, independently of anything the client sends or hides.

The one endpoint with no role check by design is the Jira status webhook (`POST /webhooks/jira/{org_slug}/{secret}`): it's called by Jira's own servers, which can't attach a bearer token, so it's gated by an unguessable 32-byte secret in the URL path instead (the same pattern Slack/Discord incoming webhooks use).

## Rate limiting

Redis-backed (`app/rate_limit.py`, via `slowapi`), keyed by authenticated user ID when a valid JWT is present, otherwise by IP — so it still protects unauthenticated endpoints like login and the Jira webhook, not just logged-in traffic. Applied selectively rather than globally, since several dashboard pages legitimately poll GET endpoints every few seconds:

| Endpoint | Limit | Why |
|---|---|---|
| `/auth/login`, `/auth/register`, `/auth/refresh` | 10/min | brute-force / credential-stuffing protection |
| `/simulate/{scenario}`, `/bas/run` | 5/min | spins up a real Kubernetes pod per call |
| `/incidents/{id}/investigate`, `/incidents/{id}/investigate-live` | 5–10/min | triggers the full LLM-backed multi-agent pipeline |
| `/chat`, `/query`, `/*/explain`, `/*/briefing` | 20/min | Groq API cost/latency protection |
| `/ingest/*` | 20/min | bulk write / storage abuse protection |
| `/webhooks/jira/{org_slug}/{secret}` | 20/min | defense-in-depth against brute-forcing the path secret |

A Redis outage degrades to **no rate limiting** rather than 500ing every request (`swallow_errors=True`) — availability over strict enforcement, since this isn't a public-abuse-prone consumer product.

## Secrets

- No credentials are committed to the repo — `.env` is gitignored; only `.env.example` (with empty/placeholder values) is tracked. CI never needs real secrets: the backend test suite runs against a temp SQLite file with `CELERY_TASK_ALWAYS_EAGER=true` and fake Neo4j/Redis doubles.
- Third-party integration credentials (Jira API token, Slack client secret) are stored as JSON in the database, protected by the database's own access control rather than a separate application-level encryption layer — a known simplification, not something to assume is hardened for a real multi-tenant SaaS.

## Dependency & container scanning

- **Dependabot** (`.github/dependabot.yml`) watches the backend's pip packages, the frontend's npm packages, GitHub Actions versions, and the base images of all three Dockerfiles — weekly.
- **Trivy** (`.github/workflows/security.yml`) builds the backend and frontend images and scans them for CRITICAL/HIGH CVEs on every push to `master` plus a weekly schedule, uploading results to GitHub's Security tab (SARIF). It doesn't fail the build on findings — base-image CVEs are often outside this project's control to fix immediately — but it makes them visible instead of invisible.

## What's deliberately out of scope

This is a solo portfolio project, not a fielded product: there's no bug bounty, no pen test, and no SOC2/ISO audit trail behind these claims — they describe what the code actually does, verified by reading it, not a compliance posture. CORS defaults to `*` origins (mitigated by `allow_credentials=False`, since the app authenticates via bearer tokens, not cookies) unless `CORS_ORIGINS` is set for a real deployment.

## Reporting an issue

This is a personal project — open a GitHub issue, or reach out directly, and I'll fix it as fast as I can.
