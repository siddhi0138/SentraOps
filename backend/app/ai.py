import json
import os
import time

from groq import Groq, GroqError

from app.metrics import ai_call_duration_seconds, ai_calls_total, ai_cost_usd_total, ai_tokens_total

DEFAULT_MODEL = "llama-3.3-70b-versatile"

# Real published Groq per-token pricing (USD per token, converted from their
# per-million-token rates as of 2026-07: $0.59/1M input, $0.79/1M output for
# llama-3.3-70b-versatile). Falls back to this same rate for any other
# GROQ_MODEL value, since Groq doesn't expose a pricing-lookup API - close
# enough to be a genuinely useful cost estimate, not exact for every model.
_PROMPT_PRICE_PER_TOKEN = 0.59 / 1_000_000
_COMPLETION_PRICE_PER_TOKEN = 0.79 / 1_000_000

SYSTEM_PROMPT = """You are CyberSentinel AI, a security analyst assistant embedded in a SOC platform.

Answer the analyst's question using ONLY the evidence provided below - real \
events and incidents from this platform's own database. Do not invent hosts, \
users, IPs, or timestamps that aren't in the evidence.

If the evidence doesn't contain enough information to answer confidently, say \
so plainly instead of guessing. When you do answer, cite the specific hosts, \
usernames, timestamps, or incident numbers from the evidence that support your \
answer. Keep the tone professional and concise, like a real analyst briefing a \
colleague. Format your answer in markdown (short paragraphs, bullet points for \
lists) but skip a top-level heading - the UI already has one."""


class ChatConfigError(RuntimeError):
    """Raised when GROQ_API_KEY isn't set - distinct from a real provider
    failure so the API layer can return a clean 503 vs. a 502."""


class ChatProviderError(RuntimeError):
    """Wraps any Groq SDK failure (auth, rate limit, timeout, ...) into one
    type the API layer can turn into a clean error response."""


def _get_client() -> Groq:
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        raise ChatConfigError("GROQ_API_KEY is not set")
    return Groq(api_key=api_key)


def _call_groq(feature: str, *, messages: list[dict], temperature: float, max_tokens: int, json_mode: bool = False):
    """The one place every Groq call in this app actually goes through -
    every agent (via chat_json) and every AI feature (chat, incident/event
    explain, NL query, the various briefings) - so instrumenting here once
    gives real AI-observability metrics (latency, token usage, estimated
    cost, success/failure rate) for the whole app, not a sampled subset of
    it. `feature` is a short label (e.g. "agent_detection",
    "incident_explain") used purely for metric cardinality, not logic."""
    client = _get_client()
    model = os.environ.get("GROQ_MODEL", DEFAULT_MODEL)
    start = time.monotonic()

    try:
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            **({"response_format": {"type": "json_object"}} if json_mode else {}),
        )
    except GroqError as exc:
        ai_calls_total.labels(feature=feature, status="error").inc()
        ai_call_duration_seconds.labels(feature=feature).observe(time.monotonic() - start)
        raise ChatProviderError(str(exc)) from exc

    duration = time.monotonic() - start
    ai_calls_total.labels(feature=feature, status="success").inc()
    ai_call_duration_seconds.labels(feature=feature).observe(duration)

    # isinstance-checked, not just truthy: response.usage on a real Groq
    # response is a real object with int fields, but plenty of existing
    # tests mock the response as a bare MagicMock() without setting .usage,
    # which auto-vivifies .usage.prompt_tokens as another MagicMock rather
    # than an int - skip metric recording rather than feeding a Counter a
    # non-numeric value (also the right defensive behavior for a real SDK
    # response that ever omits usage).
    usage = getattr(response, "usage", None)
    prompt_tokens = getattr(usage, "prompt_tokens", None)
    completion_tokens = getattr(usage, "completion_tokens", None)
    if isinstance(prompt_tokens, int) and isinstance(completion_tokens, int):
        ai_tokens_total.labels(feature=feature, token_type="prompt").inc(prompt_tokens)
        ai_tokens_total.labels(feature=feature, token_type="completion").inc(completion_tokens)
        cost = prompt_tokens * _PROMPT_PRICE_PER_TOKEN + completion_tokens * _COMPLETION_PRICE_PER_TOKEN
        ai_cost_usd_total.labels(feature=feature).inc(cost)

    return response


def chat_json(system_prompt: str, user_content: str, *, temperature: float = 0.2, max_tokens: int = 700, feature: str = "chat_json") -> dict:
    """Generic JSON-mode Groq call - the one place that owns model
    selection, JSON parsing, and provider-error translation for every
    single-shot structured call in the app, including each Milestone 3
    agent, so none of them re-implement this boilerplate."""
    response = _call_groq(
        feature,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ],
        temperature=temperature,
        max_tokens=max_tokens,
        json_mode=True,
    )

    raw = response.choices[0].message.content
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"_raw": raw}


def _format_evidence(evidence: list[dict]) -> str:
    if not evidence:
        return "(no matching evidence found in the platform's data)"

    lines = []
    for item in evidence:
        label = f"{item['content_type']} #{item['content_id']}" if item["content_id"] else item["content_type"]
        lines.append(f"[{label}]\n{item['text']}")
    return "\n\n".join(lines)


def answer_question(question: str, evidence: list[dict]) -> str:
    response = _call_groq(
        "chat",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Evidence:\n{_format_evidence(evidence)}\n\nQuestion: {question}"},
        ],
        temperature=0.2,
        max_tokens=800,
    )
    return response.choices[0].message.content


_EXPLAIN_TONE_BY_AUDIENCE = {
    "analyst": (
        "Write for a security analyst colleague: technical and precise, citing "
        "specific evidence (hosts, accounts, IPs, timestamps, event types)."
    ),
    "executive": (
        "Write for a non-technical business executive: plain language, no jargon "
        "(avoid event IDs, protocol names, or technical terms) - focus on business "
        "risk, what happened in everyday terms, and what it means for the company."
    ),
}


def _explain_system_prompt(audience: str, playbook_guidance: str = "") -> str:
    tone = _EXPLAIN_TONE_BY_AUDIENCE.get(audience, _EXPLAIN_TONE_BY_AUDIENCE["analyst"])
    # Playbook guidance comes from app/marketplace.py - an org-installed
    # "AI Marketplace" playbook adding extra instructions to this same
    # prompt, never new code execution (see PlaybookTemplate's docstring).
    guidance_block = f"\n{playbook_guidance}\n" if playbook_guidance else ""
    return f"""You are CyberSentinel AI, a security analyst assistant. Given an \
incident's report (timeline, alerts, threat intel, risk factors), produce a \
structured explanation of it.

{tone}
{guidance_block}
Respond with ONLY a JSON object (no markdown fences, no extra text) with \
exactly these string keys:
- "explanation": 2-4 sentences explaining WHY this incident has the risk \
level it does. Written for a human, not a severity label.
- "timeline_narrative": one prose paragraph (not a list) narrating how the \
attack progressed from start to finish, the way an analyst would tell the \
story to a colleague.
- "attack_type": a short label, e.g. "Credential Compromise" or \
"Ransomware / Data Exfiltration".
- "affected_user": the primary compromised/involved account, or "Unknown" \
if unclear from the evidence.
- "affected_assets": comma-separated hostnames most affected.
- "impact": one sentence on the likely business impact.

Base everything strictly on the report given - do not invent details not \
present in it."""


def _fallback_explanation(raw_text: str) -> dict:
    # The model occasionally ignores the JSON-only instruction under load;
    # degrade to showing its raw prose as the explanation rather than a 500.
    return {
        "explanation": raw_text,
        "timeline_narrative": "",
        "attack_type": "Unknown",
        "affected_user": "Unknown",
        "affected_assets": "",
        "impact": "",
    }


def explain_incident(report: str, confidence: int, audience: str = "analyst", playbook_guidance: str = "") -> dict:
    response = _call_groq(
        "incident_explain",
        messages=[
            {"role": "system", "content": _explain_system_prompt(audience, playbook_guidance)},
            {"role": "user", "content": f"Incident report:\n{report}"},
        ],
        temperature=0.2,
        max_tokens=700,
        json_mode=True,
    )

    raw = response.choices[0].message.content
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = _fallback_explanation(raw)

    # Confidence is the correlation engine's own computed value, not
    # something the LLM should estimate - keeps it consistent with what
    # the rest of the app already shows for this incident.
    parsed["confidence"] = confidence
    return parsed


_EXPLAIN_EVENT_SYSTEM_PROMPT = """You are CyberSentinel AI, a security analyst assistant. Given a \
single raw security event/log line from a SOC platform, explain it to an analyst \
who is scanning a large events table and needs to quickly decide whether it's worth \
investigating.

Respond with ONLY a JSON object (no markdown fences, no extra text) with exactly \
these string keys:
- "explanation": 1-3 sentences in plain language explaining what this event means \
and why it has the severity it does.
- "is_suspicious": either "true" or "false" (as a string) - your own judgment of \
whether this single event, in isolation, looks like it could be malicious or \
anomalous activity worth an analyst's attention, as opposed to routine/benign \
activity.
- "recommended_action": one short, concrete next step an analyst could take \
(e.g. "Check other events from this host in the last hour" or "No action needed - \
routine activity").

Base everything strictly on the event given - do not invent details not present \
in it."""


def _fallback_event_explanation(raw_text: str) -> dict:
    return {
        "explanation": raw_text,
        "is_suspicious": "false",
        "recommended_action": "",
    }


def explain_event(event_text: str) -> dict:
    response = _call_groq(
        "event_explain",
        messages=[
            {"role": "system", "content": _EXPLAIN_EVENT_SYSTEM_PROMPT},
            {"role": "user", "content": f"Event:\n{event_text}"},
        ],
        temperature=0.2,
        max_tokens=300,
        json_mode=True,
    )

    raw = response.choices[0].message.content
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = _fallback_event_explanation(raw)

    parsed["is_suspicious"] = str(parsed.get("is_suspicious", "false")).lower() == "true"
    return parsed


# Known event_type values produced by the parsers - used to ground the LLM's
# output so it maps natural language onto values the /events filter can
# actually match with an exact "==" comparison, instead of hallucinating one.
KNOWN_EVENT_TYPES = (
    "login_success",
    "login_failed",
    "privilege_escalation",
    "process_execution",
    "windows_event",
    "syslog_event",
    "http_error",
    "http_not_found",
    "http_request",
    "auth_failed",
    "firewall_deny",
    "firewall_allow",
)
KNOWN_SEVERITIES = ("low", "medium", "high", "critical")

_QUERY_SYSTEM_PROMPT = f"""You are CyberSentinel AI, a security analyst assistant. Translate the \
analyst's natural-language question into a STRUCTURED search filter for this \
platform's events table. You are NOT generating SQL, KQL, or any query \
language - only picking values for a fixed set of filter fields.

Respond with ONLY a JSON object (no markdown fences, no extra text) with \
exactly these keys, using null for any field the question doesn't specify:
- "event_type": one of {list(KNOWN_EVENT_TYPES)}, or null
- "severity": one of {list(KNOWN_SEVERITIES)}, or null
- "username": a specific account name mentioned, or null
- "host": a specific hostname mentioned, or null
- "source_ip": a specific IP address mentioned, or null
- "q": a short free-text keyword to match against usernames/hosts/IPs/\
messages/event types, for anything not captured by the fields above (e.g. a \
tool name, keyword, or vague topic), or null

Only set fields you're confident about from the question. Do not invent \
hosts, usernames, or IPs that aren't mentioned."""


def _clean_query_filters(parsed: dict) -> dict:
    event_type = parsed.get("event_type")
    if event_type not in KNOWN_EVENT_TYPES:
        event_type = None

    severity = parsed.get("severity")
    if severity not in KNOWN_SEVERITIES:
        severity = None

    def _clean_str(value) -> str | None:
        return value if isinstance(value, str) and value.strip() else None

    return {
        "event_type": event_type,
        "severity": severity,
        "username": _clean_str(parsed.get("username")),
        "host": _clean_str(parsed.get("host")),
        "source_ip": _clean_str(parsed.get("source_ip")),
        "q": _clean_str(parsed.get("q")),
    }


def translate_query(question: str) -> dict:
    response = _call_groq(
        "nl_query",
        messages=[
            {"role": "system", "content": _QUERY_SYSTEM_PROMPT},
            {"role": "user", "content": question},
        ],
        temperature=0,
        max_tokens=200,
        json_mode=True,
    )

    raw = response.choices[0].message.content
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = {}

    return _clean_query_filters(parsed)
