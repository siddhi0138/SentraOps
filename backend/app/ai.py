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


EXPLAIN_SYSTEM_PROMPT = """You are CyberSentinel AI, a security analyst assistant. \
Given an incident's report (timeline, alerts, threat intel, risk factors), \
produce a structured explanation of it.

Respond with ONLY a JSON object (no markdown fences, no extra text) with \
exactly these string keys:
- "explanation": 2-4 sentences explaining WHY this incident has the risk \
level it does, referencing specific evidence (accounts, IPs, hosts, timing). \
Written for a human, not a severity label.
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


def explain_incident(report: str, confidence: int) -> dict:
    client = _get_client()
    model = os.environ.get("GROQ_MODEL", DEFAULT_MODEL)

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": EXPLAIN_SYSTEM_PROMPT},
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
