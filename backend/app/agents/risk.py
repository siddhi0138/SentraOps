from app.ai import chat_json
from app.agents.state import AgentState, add_message, format_graph_context, format_memory_context

SYSTEM_PROMPT = """You are the Risk Assessment Agent on an autonomous AI Security Operations \
Center team. Unlike the other agents, you don't look at raw logs - you look \
at business impact. You're given what the rest of the team already found \
(attack pattern, forensic timeline, threat intel) plus this platform's own \
asset inventory (criticality/department/owner for the affected hosts). \
Combine these into a business risk assessment a non-technical executive \
would understand: not "how bad is this technically" but "how much could \
this cost or damage the business."

You may also be given a history of prior incidents involving the same \
hosts/users. A repeat offender is a bigger business concern than a first \
occurrence - factor that in - but only if that history is actually given \
to you.

You may also be given real attack-graph connectivity: other hosts and \
incidents reachable from this incident's own hosts within a couple of \
hops in the platform's actual relationship graph (shared users, shared \
IPs, shared incidents - not just this incident's own event data). Wider \
graph connectivity is a real business-risk amplifier - lateral spread \
potential, not just this incident in isolation - but only factor it in if \
that graph data is actually given to you, and never claim spread to \
hosts/incidents not explicitly listed.

Respond with ONLY a JSON object (no markdown fences, no extra text) with \
exactly these keys:
- "business_risk_score": integer 0-100.
- "business_risk_level": one of "low", "medium", "high", "critical".
- "explanation": 2-3 sentences justifying the score in business terms \
(which asset/department is exposed, what data or operations are at risk).
- "most_critical_asset": the single hostname most driving this score, or \
null if the asset inventory didn't include enough information.

Base this on the asset criticality/department/owner data and the other \
agents' findings given to you - do not invent assets or departments not \
listed."""


def run(state: AgentState) -> dict:
    assets = state.get("known_assets") or []
    assets_text = (
        "\n".join(
            f"- {a['host']}: criticality={a['criticality']}, department={a.get('department') or 'unknown'}, owner={a.get('owner') or 'unknown'}"
            for a in assets
        )
        if assets
        else "(no asset inventory data available for the affected hosts)"
    )
    detection = state.get("detection") or {}
    investigation = state.get("investigation") or {}
    threat_intel = state.get("threat_intel_findings") or {}
    memory = state.get("known_memory") or {}
    repeat_text = format_memory_context(
        {"repeat_hosts": memory.get("repeat_hosts"), "repeat_users": memory.get("repeat_users")}
    )
    graph_text = format_graph_context(state.get("known_graph_context") or {})

    user_content = (
        f"Incident: {state['incident']['title']}\n"
        f"Detection Agent: {detection.get('assessment', 'n/a')}\n"
        f"Investigation Agent: {investigation.get('timeline_narrative', 'n/a')} "
        f"(attacker objective: {investigation.get('attacker_objective', 'unclear')})\n"
        f"Threat Intel Agent: {threat_intel.get('summary', 'n/a')}\n\n"
        f"Affected asset inventory:\n{assets_text}\n\n"
        f"Prior incident history for these hosts/users:\n{repeat_text}\n\n"
        f"Attack graph connectivity:\n{graph_text}"
    )
    result = chat_json(SYSTEM_PROMPT, user_content, max_tokens=350, feature="agent_risk")

    score = result.get("business_risk_score", state["incident"]["risk_score"])
    level = result.get("business_risk_level", state["incident"]["risk_level"])
    risk = {
        "business_risk_score": score,
        "business_risk_level": level,
        "explanation": result.get("explanation", result.get("_raw", "")),
        "most_critical_asset": result.get("most_critical_asset"),
    }
    message = f"Business risk {score}/100 ({level}). {risk['explanation']}"

    return {
        "risk": risk,
        "messages": add_message(state, "risk", message),
        "stage": "risk",
    }
