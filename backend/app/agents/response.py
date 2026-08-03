from app.ai import chat_json
from app.agents.state import AgentState, add_message

SYSTEM_PROMPT = """You are the Response Agent on an autonomous AI Security Operations Center \
team - an Incident Response planner. You're given everything the rest of \
the team found (detection, investigation, threat intel, business risk). \
Propose the specific containment, eradication, and recovery actions a \
human responder should take. You NEVER execute anything yourself - every \
action you propose requires explicit human approval before it happens, so \
phrase actions as concrete, specific instructions a person could act on.

Respond with ONLY a JSON object (no markdown fences, no extra text) with \
exactly these keys:
- "actions": a list of up to 6 objects, each with "category" (one of \
"containment", "eradication", "recovery") and "description" (one specific, \
actionable sentence, e.g. "Disable account svc_update and force a password \
reset").
- "urgency": one of "low", "medium", "high", "immediate" - how quickly a \
human should act on these.

Ground every action in the specific hosts/accounts/IPs the team already \
found - do not propose generic advice or actions against systems that \
were never mentioned."""


def run(state: AgentState) -> dict:
    detection = state.get("detection") or {}
    investigation = state.get("investigation") or {}
    threat_intel = state.get("threat_intel_findings") or {}
    risk = state.get("risk") or {}

    user_content = (
        f"Incident: {state['incident']['title']}\n"
        f"Detection: {detection.get('assessment', 'n/a')}\n"
        f"Investigation: {investigation.get('timeline_narrative', 'n/a')}\n"
        f"Threat Intel: {threat_intel.get('summary', 'n/a')}\n"
        f"Business Risk: {risk.get('business_risk_level', 'n/a')} - {risk.get('explanation', 'n/a')}\n"
        f"Already-known baseline recommendations: {'; '.join(state.get('known_recommended_actions') or []) or 'none'}"
    )
    result = chat_json(SYSTEM_PROMPT, user_content, max_tokens=500, feature="agent_response")

    actions = result.get("actions", [])
    response = {
        "proposed_actions": actions,
        "urgency": result.get("urgency", "medium"),
        "requires_approval": True,
    }
    message = f"Proposing {len(actions)} action(s), urgency {response['urgency']} - all pending human approval."

    return {
        "response": response,
        "messages": add_message(state, "response", message),
        "stage": "response",
    }
