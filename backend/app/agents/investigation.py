from app.ai import chat_json
from app.agents.state import AgentState, add_message, format_graph_context, format_timeline

SYSTEM_PROMPT = """You are the Investigation Agent on an autonomous AI Security Operations Center \
team - a Digital Forensics Expert. The Detection Agent has already flagged \
this cluster of events as a likely attack pattern; your job is to dig \
deeper into the raw event timeline and reconstruct exactly what happened, \
step by step, the way a forensic analyst building a case would.

You may also be given real attack-graph connectivity: other hosts/incidents \
reachable from this incident's own hosts within a couple of hops in the \
platform's actual relationship graph. If given, and if relevant, note \
lateral-movement potential in your findings - but only reference hosts or \
incidents actually listed in that graph data, never invent one.

Respond with ONLY a JSON object (no markdown fences, no extra text) with \
exactly these keys:
- "timeline_narrative": one prose paragraph narrating the attack \
chronologically from the first event to the last - what the attacker did, \
in what order, and on which hosts/accounts.
- "key_findings": a list of up to 6 short, specific forensic findings \
(e.g. "PowerShell executed with encoded command on FINANCE-PC-21 at \
09:22:31"), each grounded in a specific event from the timeline.
- "attacker_objective": one short phrase for what the attacker appears to \
be after (e.g. "data exfiltration", "persistent access", "unclear").

Base everything strictly on the events given - do not invent hosts, users, \
or timestamps that aren't present."""


def run(state: AgentState) -> dict:
    detection = state.get("detection") or {}
    graph_text = format_graph_context(state.get("known_graph_context") or {})
    user_content = (
        f"Incident candidate: {state['incident']['title']}\n"
        f"Detection Agent's assessment: {detection.get('assessment', 'n/a')} "
        f"(attack pattern: {detection.get('attack_pattern', 'unclear')})\n\n"
        f"Full event timeline:\n{format_timeline(state['timeline'])}\n\n"
        f"Attack graph connectivity:\n{graph_text}"
    )
    result = chat_json(SYSTEM_PROMPT, user_content, max_tokens=700, feature="agent_investigation")

    investigation = {
        "timeline_narrative": result.get("timeline_narrative", result.get("_raw", "")),
        "key_findings": result.get("key_findings", []),
        "attacker_objective": result.get("attacker_objective", "unclear"),
    }
    message = f"Objective appears to be {investigation['attacker_objective']}. {investigation['timeline_narrative']}"

    return {
        "investigation": investigation,
        "messages": add_message(state, "investigation", message),
        "stage": "investigation",
    }
