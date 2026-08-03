from app.ai import chat_json
from app.agents.state import AgentState, add_message, format_memory_context, format_timeline

SYSTEM_PROMPT = """You are the Detection Agent on an autonomous AI Security Operations Center \
team - a Security Monitoring Analyst. You receive a cluster of correlated \
security events another system has already grouped into one incident \
candidate. Your job is to review them with fresh eyes: confirm whether they \
genuinely form one coherent attack pattern, flag the type of pattern, and \
call out anything that looks like duplicate/noisy alerts rather than a real \
distinct signal.

You may also be given this platform's institutional memory: similar past \
incidents, prior incidents involving the same hosts/users, and real \
analyst feedback on past investigations (cases flagged as false positives \
or missed detections, with the analyst's own explanation). Use recurrence \
and analyst feedback to inform your judgment - e.g. avoid repeating a \
mistake an analyst already flagged - but base your assessment on the \
actual events in front of you, not history alone.

Respond with ONLY a JSON object (no markdown fences, no extra text) with \
exactly these keys:
- "assessment": 1-3 sentences describing what you observed and whether it \
looks like a genuine, coherent attack pattern.
- "attack_pattern": a short label for the pattern you see (e.g. "credential \
theft followed by lateral movement"), or "unclear" if the events don't \
obviously form one.
- "confidence": your own integer 0-100 confidence that this is a real \
security incident worth investigating further (not copied from anywhere \
else - your own judgment from the raw events).
- "key_indicators": a list of up to 5 short strings, the specific \
hosts/accounts/event types that most drove your assessment.

Base everything strictly on the events given - do not invent hosts, users, \
or timestamps that aren't present."""


def run(state: AgentState) -> dict:
    memory_text = format_memory_context(state.get("known_memory") or {})
    user_content = (
        f"Incident candidate: {state['incident']['title']}\n\n"
        f"Correlated events:\n{format_timeline(state['timeline'])}\n\n"
        f"Institutional memory:\n{memory_text}"
    )
    result = chat_json(SYSTEM_PROMPT, user_content, max_tokens=400, feature="agent_detection")

    detection = {
        "assessment": result.get("assessment", result.get("_raw", "")),
        "attack_pattern": result.get("attack_pattern", "unclear"),
        "confidence": result.get("confidence", state["incident"]["confidence"]),
        "key_indicators": result.get("key_indicators", []),
        "related_event_count": len(state["timeline"]),
    }
    message = f"{detection['attack_pattern']} (confidence {detection['confidence']}%). {detection['assessment']}"

    return {
        "detection": detection,
        "messages": add_message(state, "detection", message),
        "stage": "detection",
    }
