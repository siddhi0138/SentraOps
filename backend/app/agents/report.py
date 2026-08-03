from app.ai import chat_json
from app.agents.state import AgentState, add_message

SYSTEM_PROMPT = """You are the Report Agent on an autonomous AI Security Operations Center \
team. You're given everything the rest of the team found across the whole \
investigation (detection, forensic investigation, threat intel, business \
risk, proposed response actions) and write the final incident report - \
completely from that evidence, no templates.

Respond with ONLY a JSON object (no markdown fences, no extra text) with \
exactly these keys:
- "executive_summary": 2-4 sentences for a non-technical executive - plain \
language, no jargon, focused on business impact and what's being done \
about it.
- "technical_summary": 2-4 sentences for a security analyst colleague - \
technical and precise, citing the specific hosts/accounts/techniques the \
team found.
- "compliance_notes": 1-3 sentences on regulatory/compliance relevance - \
what kind of data or systems were exposed and whether this looks like \
something that would trigger breach-notification obligations. Say plainly \
if there isn't enough information to judge this.
- "customer_notification": one sentence recommending whether and how \
affected customers/users should be notified, or "Not applicable" if \
nothing customer-facing was affected.

Base everything strictly on the findings given - do not invent facts not \
present in them."""


def run(state: AgentState) -> dict:
    detection = state.get("detection") or {}
    investigation = state.get("investigation") or {}
    threat_intel = state.get("threat_intel_findings") or {}
    risk = state.get("risk") or {}
    response = state.get("response") or {}

    actions_text = "; ".join(
        f"[{a.get('category', '?')}] {a.get('description', '')}" for a in response.get("proposed_actions", [])
    ) or "none proposed"

    user_content = (
        f"Incident: {state['incident']['title']}\n"
        f"Detection Agent: {detection.get('assessment', 'n/a')} (pattern: {detection.get('attack_pattern', 'n/a')})\n"
        f"Investigation Agent: {investigation.get('timeline_narrative', 'n/a')} "
        f"(objective: {investigation.get('attacker_objective', 'unclear')})\n"
        f"Threat Intel Agent: {threat_intel.get('summary', 'n/a')}\n"
        f"Risk Agent: {risk.get('business_risk_level', 'n/a')} risk ({risk.get('business_risk_score', 'n/a')}/100) - "
        f"{risk.get('explanation', 'n/a')}\n"
        f"Response Agent proposed actions ({response.get('urgency', 'n/a')} urgency): {actions_text}"
    )
    result = chat_json(SYSTEM_PROMPT, user_content, max_tokens=500, feature="agent_report")

    report = {
        "executive_summary": result.get("executive_summary", result.get("_raw", "")),
        "technical_summary": result.get("technical_summary", ""),
        "compliance_notes": result.get("compliance_notes", ""),
        "customer_notification": result.get("customer_notification", "Not applicable"),
    }
    message = f"Final report ready. {report['executive_summary']}"

    return {
        "report": report,
        "messages": add_message(state, "report", message),
        "stage": "done",
    }
