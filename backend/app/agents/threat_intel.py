from app.ai import chat_json
from app.agents.state import AgentState, add_message, format_timeline

SYSTEM_PROMPT = """You are the Threat Intelligence Agent on an autonomous AI Security Operations \
Center team. You do NOT have live access to external feeds (VirusTotal, \
AbuseIPDB, CISA advisories) - you're given whatever this platform's own \
mock IOC feed already matched, plus the raw event timeline. Your job is \
twofold:
1. Summarize what the known IOC matches mean for this incident.
2. Classify the observed attacker behavior against the public MITRE ATT&CK \
framework - this is pattern classification from your own knowledge of \
ATT&CK, not a live lookup, and must be phrased that way.

Respond with ONLY a JSON object (no markdown fences, no extra text) with \
exactly these keys:
- "summary": 1-3 sentences on what the threat intel picture looks like for \
this incident, referencing specific known IOC matches if any were given.
- "mitre_techniques": a list of up to 5 objects, each with "id" (e.g. \
"T1078"), "name" (e.g. "Valid Accounts"), and "evidence" (the specific \
event/behavior that maps to it). Only include techniques you can point to \
specific evidence for.
- "malware_association": a malware family name if the known IOC matches \
named one, else null.
- "confidence": integer 0-100, how confident you are in this threat intel \
picture given what little external data is actually available.

Do not invent IOC matches, CVEs, or malware family names that aren't \
either in the known matches given to you or a reasonable ATT&CK technique \
classification of the literal behavior in the timeline."""


def run(state: AgentState) -> dict:
    known = state.get("known_threat_intel") or []
    known_text = (
        "\n".join(f"- {m['indicator']} ({m['indicator_type']}): {m['verdict']} - {m['confidence']}% ({m['source']})" for m in known)
        if known
        else "(no known IOC matches from the platform's mock feed)"
    )
    user_content = (
        f"Incident: {state['incident']['title']}\n\n"
        f"Known IOC matches:\n{known_text}\n\n"
        f"Event timeline:\n{format_timeline(state['timeline'])}"
    )
    result = chat_json(SYSTEM_PROMPT, user_content, max_tokens=500, feature="agent_threat_intel")

    findings = {
        "summary": result.get("summary", result.get("_raw", "")),
        "mitre_techniques": result.get("mitre_techniques", []),
        "malware_association": result.get("malware_association"),
        "matches": known,
        "confidence": result.get("confidence", 0),
    }
    technique_ids = ", ".join(t.get("id", "?") for t in findings["mitre_techniques"]) or "none identified"
    message = f"{findings['summary']} MITRE techniques: {technique_ids}."

    return {
        "threat_intel_findings": findings,
        "messages": add_message(state, "threat_intel", message),
        "stage": "threat_intel",
    }
