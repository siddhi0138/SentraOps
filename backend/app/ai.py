import json
import os

from groq import Groq, GroqError

DEFAULT_MODEL = "llama-3.3-70b-versatile"

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


def _format_evidence(evidence: list[dict]) -> str:
    if not evidence:
        return "(no matching evidence found in the platform's data)"

    lines = []
    for item in evidence:
        label = f"{item['content_type']} #{item['content_id']}" if item["content_id"] else item["content_type"]
        lines.append(f"[{label}]\n{item['text']}")
    return "\n\n".join(lines)


def answer_question(question: str, evidence: list[dict]) -> str:
    client = _get_client()
    model = os.environ.get("GROQ_MODEL", DEFAULT_MODEL)

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Evidence:\n{_format_evidence(evidence)}\n\nQuestion: {question}"},
            ],
            temperature=0.2,
            max_tokens=800,
        )
    except GroqError as exc:
        raise ChatProviderError(str(exc)) from exc

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


def _explain_system_prompt(audience: str) -> str:
    tone = _EXPLAIN_TONE_BY_AUDIENCE.get(audience, _EXPLAIN_TONE_BY_AUDIENCE["analyst"])
    return f"""You are CyberSentinel AI, a security analyst assistant. Given an \
incident's report (timeline, alerts, threat intel, risk factors), produce a \
structured explanation of it.

{tone}

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


def explain_incident(report: str, confidence: int, audience: str = "analyst") -> dict:
    client = _get_client()
    model = os.environ.get("GROQ_MODEL", DEFAULT_MODEL)

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": _explain_system_prompt(audience)},
                {"role": "user", "content": f"Incident report:\n{report}"},
            ],
            temperature=0.2,
            max_tokens=700,
            response_format={"type": "json_object"},
        )
    except GroqError as exc:
        raise ChatProviderError(str(exc)) from exc

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
    client = _get_client()
    model = os.environ.get("GROQ_MODEL", DEFAULT_MODEL)

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": _EXPLAIN_EVENT_SYSTEM_PROMPT},
                {"role": "user", "content": f"Event:\n{event_text}"},
            ],
            temperature=0.2,
            max_tokens=300,
            response_format={"type": "json_object"},
        )
    except GroqError as exc:
        raise ChatProviderError(str(exc)) from exc

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
    client = _get_client()
    model = os.environ.get("GROQ_MODEL", DEFAULT_MODEL)

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": _QUERY_SYSTEM_PROMPT},
                {"role": "user", "content": question},
            ],
            temperature=0,
            max_tokens=200,
            response_format={"type": "json_object"},
        )
    except GroqError as exc:
        raise ChatProviderError(str(exc)) from exc

    raw = response.choices[0].message.content
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = {}

    return _clean_query_filters(parsed)
