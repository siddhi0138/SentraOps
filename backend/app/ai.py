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
