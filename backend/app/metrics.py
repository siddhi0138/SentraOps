from prometheus_client import Counter, Histogram

# HTTP-level metrics (request rate/latency/status by route) are handled by
# prometheus_fastapi_instrumentator in main.py - these are the metrics that
# actually matter for this project specifically: the multi-agent
# investigation pipeline, which a generic HTTP instrumentator can't see
# inside of (one HTTP request can contain a ~10s, 6-LLM-call chain).

agent_investigations_total = Counter(
    "cybersentinel_agent_investigations_total",
    "Total multi-agent investigations, by final status",
    ["status"],
)

agent_investigation_duration_seconds = Histogram(
    "cybersentinel_agent_investigation_duration_seconds",
    "Wall-clock duration of a multi-agent investigation, start to persisted result",
    buckets=(1, 2, 5, 10, 15, 20, 30, 60, 120),
)

# AI observability: every individual Groq call this app makes (all six
# agents, chat, incident/event explanation, NL query, executive/compliance/
# predictive/digital-twin briefings) goes through app/ai.py's single
# _call_groq() wrapper, which records these - one real instrumentation
# point covers every AI feature in the app, not a sampled subset.

ai_calls_total = Counter(
    "cybersentinel_ai_calls_total",
    "Total Groq API calls, by feature and outcome",
    ["feature", "status"],
)

ai_call_duration_seconds = Histogram(
    "cybersentinel_ai_call_duration_seconds",
    "Wall-clock duration of a single Groq API call",
    ["feature"],
    buckets=(0.25, 0.5, 1, 2, 3, 5, 8, 12, 20, 30),
)

ai_tokens_total = Counter(
    "cybersentinel_ai_tokens_total",
    "Total Groq tokens consumed, by feature and token type",
    ["feature", "token_type"],
)

ai_cost_usd_total = Counter(
    "cybersentinel_ai_cost_usd_total",
    "Estimated Groq API cost in USD, by feature (based on published per-model token pricing)",
    ["feature"],
)
