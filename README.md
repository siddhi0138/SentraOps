# CyberSentinel AI

An AI Security Team for SMEs: multiple specialized agents investigate an
incident end-to-end — detection, forensic timeline reconstruction, threat
intel enrichment, risk scoring, response recommendation, and executive
reporting — instead of dumping raw alerts on a human analyst.

## Status

Milestone 1 thin slice: a rule-based pipeline that runs a synthetic
phishing → credential theft → privilege escalation → data exfiltration
scenario through all six agents and produces a readable incident report.
No ML models, LLM calls, or streaming infra yet — those land in later
milestones once this core loop is solid.

## Agent pipeline

```
logs -> Detection -> Investigation -> Threat Intel -> Risk -> Response -> Report
```

Each agent lives in `backend/app/agents/` and takes the previous agent's
output as input. `backend/app/pipeline.py` wires them together.

## Run it

```bash
cd backend
pip install -r requirements.txt

# CLI demo - runs the sample scenario and prints the report
python run_demo.py

# API server
uvicorn app.main:app --reload
# then POST to http://127.0.0.1:8000/investigate (uses the same sample data)
```

## Roadmap

1. **Core SOC platform** (this milestone) — log ingestion, detection rules,
   investigation timeline, dashboard-ready output.
2. **Agentic intelligence** — swap rule-based agents for LLM reasoning
   (LangGraph), real threat intel lookups, ML anomaly scoring.
3. **Automation & integrations** — actually execute response actions,
   export reports, connectors (Jira, Slack, SIEMs).
4. **Enterprise polish** — Kafka/Spark streaming ingestion, Neo4j attack
   graphs, RBAC, monitoring, deployment.
