import httpx
from sqlalchemy.orm import Session

from app.ai import ChatConfigError, ChatProviderError, answer_question
from app.confidence import compute_dual_evidence_confidence
from app.db_models import AgentRun, AnalystFeedback, ConnectorInstance, Incident, ProposedAction, User
from app.executive import generate_briefing, get_summary
from app.rag import search as rag_search
from app.slack_oauth import FRONTEND_URL
from app.tasks import investigate_incident_task

SLACK_API = "https://slack.com/api"

_AGENT_DISPLAY_NAMES = {
    "detection": "Detection Agent",
    "investigation": "Investigation Agent",
    "threat_intel": "Threat Intelligence Agent",
    "risk": "Risk Agent",
    "response": "Response Agent",
    "report": "Report Agent",
}

_RATING_LABEL = {"accurate": "Accurate", "false_positive": "False Positive", "missed_detection": "Missed Detection"}


def get_org_slack_connector(db: Session, organization_id: int) -> ConnectorInstance | None:
    return (
        db.query(ConnectorInstance)
        .filter(
            ConnectorInstance.organization_id == organization_id,
            ConnectorInstance.plugin_key == "slack",
            ConnectorInstance.enabled.is_(True),
        )
        .first()
    )


def find_connector_by_team_id(db: Session, team_id: str) -> ConnectorInstance | None:
    """Slack's slash-command/interaction payloads identify the workspace by
    team_id, not organization_id. There's no portable way to filter a JSON
    column's nested key across both this project's SQLite (dev) and
    Postgres (prod) dialects (app/rag.py hits the same SQLite/Postgres split
    and makes the same call), so this scans enabled Slack connectors in
    Python - fine at the scale of "Slack workspaces connected to this app,"
    which is one per org, not a hot path queried per-event."""
    instances = (
        db.query(ConnectorInstance)
        .filter(ConnectorInstance.plugin_key == "slack", ConnectorInstance.enabled.is_(True))
        .all()
    )
    for instance in instances:
        if (instance.config or {}).get("team_id") == team_id:
            return instance
    return None


def _post_message(webhook_url: str, blocks: list[dict], text: str) -> None:
    # Deliberately the incoming-webhook URL (from the OAuth response), not
    # chat.postMessage with the bot token - chat.postMessage requires the
    # bot to actually be a *member* of the target channel (fails with
    # "not_in_channel" otherwise, confirmed against a real workspace), while
    # the incoming webhook is pre-authorized for exactly the one channel the
    # installing user picked on Slack's consent screen, no membership
    # needed. Accepts the same "blocks" shape chat.postMessage does,
    # including interactive action blocks - the Approve/Reject/Investigate
    # buttons work identically either way.
    httpx.post(webhook_url, json={"blocks": blocks, "text": text}, timeout=10)


def _resolve_channel_id(token: str, channel_name: str) -> str | None:
    """Looks up a public channel's id by name via conversations.list - the
    mechanism behind routing critical incidents to a second, admin-chosen
    channel beyond the one incoming-webhook install channel. Scans one page
    (200 channels) - fine for the kind of purpose-built #critical-incidents
    channel this is meant to find, not built for a workspace with hundreds
    of channels."""
    name = channel_name.lstrip("#")
    try:
        response = httpx.get(
            f"{SLACK_API}/conversations.list",
            headers={"Authorization": f"Bearer {token}"},
            params={"limit": 200, "types": "public_channel"},
            timeout=10,
        )
        data = response.json()
    except httpx.HTTPError:
        return None
    if not data.get("ok"):
        return None
    for channel in data.get("channels", []):
        if channel.get("name") == name:
            return channel.get("id")
    return None


def _post_to_channel(token: str, channel_id: str, blocks: list[dict], text: str) -> bool:
    """chat.postMessage with the chat:write.public scope - unlike
    _post_message's incoming-webhook path (locked to the one channel picked
    at install), this can target any public channel in the workspace
    without the bot needing to already be a member of it, which is what
    makes routing to a second, admin-chosen channel possible at all."""
    try:
        response = httpx.post(
            f"{SLACK_API}/chat.postMessage",
            headers={"Authorization": f"Bearer {token}"},
            json={"channel": channel_id, "blocks": blocks, "text": text},
            timeout=10,
        )
        return bool(response.json().get("ok"))
    except httpx.HTTPError:
        return False


def _maybe_post_to_critical_channel(db: Session, connector: ConnectorInstance, incident: Incident, blocks: list[dict], text: str) -> None:
    """Additive, not a replacement: a critical incident still posts to the
    default channel via notify_new_incident's own _post_message call - this
    is the *extra* copy into a dedicated channel, for orgs that configured
    one (PATCH /connectors/{id} with {"config": {"critical_channel": "..."}}).
    A no-op for any org that hasn't set critical_channel, or for
    non-critical incidents."""
    if incident.risk_level != "critical":
        return
    config = connector.config or {}
    critical_channel_name = config.get("critical_channel")
    token = config.get("access_token")
    if not critical_channel_name or not token:
        return

    channel_id = config.get("critical_channel_id")
    if not channel_id:
        channel_id = _resolve_channel_id(token, critical_channel_name)
        if not channel_id:
            return
        # Cache the resolved id so every subsequent critical incident skips
        # the conversations.list round-trip - only re-resolved if the admin
        # changes critical_channel (see the PATCH endpoint in main.py, which
        # clears critical_channel_id whenever critical_channel changes).
        connector.config = {**config, "critical_channel_id": channel_id}
        db.commit()

    _post_to_channel(token, channel_id, blocks, text)


def notify_new_incident(db: Session, incident: Incident) -> None:
    """Fired right after correlation.py creates a new incident (see its
    _notify_responders call site) - posts an alert to the org's connected
    Slack channel, if any. Never raises: a Slack outage or a workspace that
    revoked the app must never break correlation, the same reasoning
    app/confidence.py fails open on a Neo4j outage."""
    connector = get_org_slack_connector(db, incident.organization_id)
    if not connector:
        return
    webhook_url = (connector.config or {}).get("incoming_webhook_url")
    if not webhook_url:
        return

    incident_url = f"{FRONTEND_URL}/incidents/{incident.id}"
    blocks = [
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*<{incident_url}|New {incident.risk_level} incident: {incident.title}>*"}},
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Risk score:*\n{incident.risk_score}/100"},
                {"type": "mrkdwn", "text": f"*Confidence:*\n{incident.confidence}%"},
                {"type": "mrkdwn", "text": f"*Affected hosts:*\n{', '.join(incident.affected_hosts[:5]) or 'none'}"},
                {"type": "mrkdwn", "text": f"*Status:*\n{incident.status}"},
            ],
        },
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Investigate"},
                    "style": "primary",
                    "value": str(incident.id),
                    "action_id": "investigate_incident",
                },
                {"type": "button", "text": {"type": "plain_text", "text": "View in SentraOps"}, "url": incident_url, "action_id": "view_incident"},
            ],
        },
    ]
    text = f"New {incident.risk_level} incident: {incident.title}"
    try:
        _post_message(webhook_url, blocks, text=text)
    except httpx.HTTPError:
        pass

    _maybe_post_to_critical_channel(db, connector, incident, blocks, text)


def notify_proposed_actions(db: Session, incident: Incident, proposed_actions: list[ProposedAction]) -> None:
    """Fired right after an investigation persists its Response Agent
    proposals (see agents/runner.py's persist_investigation_result) - one
    Slack message per proposed action with real Approve/Reject buttons,
    wired to the same status transition as PATCH /proposed-actions/{id}
    (see /slack/interactions in main.py). Never raises, same reasoning as
    notify_new_incident."""
    if not proposed_actions:
        return
    connector = get_org_slack_connector(db, incident.organization_id)
    if not connector:
        return
    webhook_url = (connector.config or {}).get("incoming_webhook_url")
    if not webhook_url:
        return

    incident_url = f"{FRONTEND_URL}/incidents/{incident.id}"
    try:
        for action in proposed_actions:
            blocks = [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Proposed {action.category} action* for <{incident_url}|incident #{incident.id}>:\n{action.description}",
                    },
                },
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "Approve"},
                            "style": "primary",
                            "value": f"{action.id}:approved",
                            "action_id": "review_action",
                        },
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "Reject"},
                            "style": "danger",
                            "value": f"{action.id}:rejected",
                            "action_id": "review_action",
                        },
                    ],
                },
            ]
            _post_message(webhook_url, blocks, text=f"Proposed action for incident #{incident.id}: {action.description}")
    except httpx.HTTPError:
        pass


def notify_agent_progress(db: Session, run: AgentRun, incident: Incident, agent_name: str, message: str | None) -> None:
    """Fired once per agent as a live investigation (the async
    /investigate-live path, app/tasks.py's run_investigation_job) progresses
    - the same per-agent updates the WebSocket-driven AI Team page already
    shows live inside the app, mirrored to Slack so a SOC team can watch an
    investigation happen without opening the dashboard. Never raises, same
    reasoning as notify_new_incident."""
    connector = get_org_slack_connector(db, run.organization_id)
    if not connector:
        return
    webhook_url = (connector.config or {}).get("incoming_webhook_url")
    if not webhook_url:
        return

    display_name = _AGENT_DISPLAY_NAMES.get(agent_name, agent_name.replace("_", " ").title())
    incident_url = f"{FRONTEND_URL}/incidents/{incident.id}"
    text = f"*{display_name}* completed for <{incident_url}|incident #{incident.id}>"
    if message:
        text += f"\n{message[:400]}"
    try:
        _post_message(webhook_url, [{"type": "section", "text": {"type": "mrkdwn", "text": text}}], text=text)
    except httpx.HTTPError:
        pass


def notify_run_failed(db: Session, run: AgentRun, incident: Incident, error: str | None) -> None:
    connector = get_org_slack_connector(db, run.organization_id)
    if not connector:
        return
    webhook_url = (connector.config or {}).get("incoming_webhook_url")
    if not webhook_url:
        return

    incident_url = f"{FRONTEND_URL}/incidents/{incident.id}"
    text = f":warning: Investigation failed for <{incident_url}|incident #{incident.id}>: {error or 'unknown error'}"
    try:
        _post_message(webhook_url, [{"type": "section", "text": {"type": "mrkdwn", "text": text}}], text=text)
    except httpx.HTTPError:
        pass


def notify_feedback(db: Session, feedback: AnalystFeedback) -> None:
    """Fired after an analyst submits Learning Loop feedback on an incident
    (app/learning.py's record_feedback) - surfaces corrections in Slack
    instead of only inside the app's Learning Loop tab. Never raises, same
    reasoning as notify_new_incident."""
    connector = get_org_slack_connector(db, feedback.organization_id)
    if not connector:
        return
    webhook_url = (connector.config or {}).get("incoming_webhook_url")
    if not webhook_url:
        return

    reviewer = db.get(User, feedback.reviewed_by_id) if feedback.reviewed_by_id else None
    reviewer_label = reviewer.email if reviewer else "someone"
    label = _RATING_LABEL.get(feedback.rating, feedback.rating)
    incident_url = f"{FRONTEND_URL}/incidents/{feedback.incident_id}"
    text = f"*Learning Loop*: {reviewer_label} marked <{incident_url}|incident #{feedback.incident_id}> as *{label}*"
    if feedback.note:
        text += f"\n> {feedback.note[:300]}"
    try:
        _post_message(webhook_url, [{"type": "section", "text": {"type": "mrkdwn", "text": text}}], text=text)
    except httpx.HTTPError:
        pass


def send_daily_summaries(db: Session) -> None:
    """Celery Beat hook (app/celery_app.py's beat_schedule + the
    daily_slack_summaries_task in app/tasks.py) - posts the same AI
    executive briefing /sentraops summary generates on demand, once per org
    with an enabled Slack connector, without anyone having to ask. Skips an
    org silently (not an error) if Groq isn't configured/reachable, same
    fail-open reasoning as every other notify_* function here."""
    connectors = (
        db.query(ConnectorInstance)
        .filter(ConnectorInstance.plugin_key == "slack", ConnectorInstance.enabled.is_(True))
        .all()
    )
    for connector in connectors:
        webhook_url = (connector.config or {}).get("incoming_webhook_url")
        if not webhook_url:
            continue
        summary = get_summary(db, connector.organization_id)
        try:
            briefing = generate_briefing(summary)
        except (ChatConfigError, ChatProviderError):
            continue
        text = f"*Daily SentraOps Summary*\n*{briefing['headline']}*\n{briefing['summary']}"
        try:
            _post_message(webhook_url, [{"type": "section", "text": {"type": "mrkdwn", "text": text}}], text=text)
        except httpx.HTTPError:
            pass


def handle_slash_command(db: Session, team_id: str, text: str) -> dict:
    """Returns the JSON body /slack/commands should send back verbatim -
    Slack renders {"response_type", "text"} as the immediate reply in the
    channel/DM the command was typed in."""
    connector = find_connector_by_team_id(db, team_id)
    if not connector:
        return {"response_type": "ephemeral", "text": "This Slack workspace isn't connected to a SentraOps organization."}

    organization_id = connector.organization_id
    parts = text.strip().split(maxsplit=1)
    sub = parts[0].lower() if parts else "status"
    arg = parts[1] if len(parts) > 1 else ""

    if sub == "investigate" and arg:
        return _cmd_investigate(db, connector, organization_id, arg.strip())
    if sub == "incidents":
        return _cmd_incidents(db, organization_id)
    if sub == "summary":
        return _cmd_summary(db, organization_id)
    if sub == "ask" and arg:
        return _cmd_ask(db, organization_id, arg.strip())
    if sub == "hunt" and arg:
        return _cmd_hunt(db, organization_id, arg.strip())
    return _cmd_status(db, organization_id)


def _cmd_status(db: Session, organization_id: int) -> dict:
    summary = get_summary(db, organization_id)
    text = (
        f"*SentraOps status*\n"
        f"Open critical: {summary['open_critical_incidents']} | Open high: {summary['open_high_incidents']}\n"
        f"Pending actions: {summary['pending_actions']} | Running investigations: {summary['running_investigations']}"
    )
    return {"response_type": "ephemeral", "text": text}


def _cmd_incidents(db: Session, organization_id: int) -> dict:
    incidents = (
        db.query(Incident)
        .filter(Incident.organization_id == organization_id, Incident.status == "open")
        .order_by(Incident.risk_score.desc())
        .limit(5)
        .all()
    )
    if not incidents:
        return {"response_type": "ephemeral", "text": "No open incidents."}
    lines = [f"- <{FRONTEND_URL}/incidents/{i.id}|#{i.id} {i.title}> - {i.risk_level} ({i.risk_score}/100)" for i in incidents]
    return {"response_type": "ephemeral", "text": "*Open incidents (top 5 by risk):*\n" + "\n".join(lines)}


def _cmd_summary(db: Session, organization_id: int) -> dict:
    summary = get_summary(db, organization_id)
    try:
        briefing = generate_briefing(summary)
    except ChatConfigError:
        return {"response_type": "ephemeral", "text": "AI summary isn't configured - GROQ_API_KEY is not set."}
    except ChatProviderError as exc:
        return {"response_type": "ephemeral", "text": f"AI summary is temporarily unavailable: {exc}"}
    return {"response_type": "ephemeral", "text": f"*{briefing['headline']}*\n{briefing['summary']}"}


def _cmd_ask(db: Session, organization_id: int, question: str) -> dict:
    """/sentraops ask <question> - the same grounded RAG chat as the AI
    Analyst page, plus the dual-evidence confidence score (app/confidence.py),
    just reachable from Slack instead of the dashboard."""
    evidence = rag_search(db, organization_id, question, k=8)
    try:
        answer = answer_question(question, evidence)
    except ChatConfigError:
        return {"response_type": "ephemeral", "text": "AI chat isn't configured - GROQ_API_KEY is not set."}
    except ChatProviderError as exc:
        return {"response_type": "ephemeral", "text": f"AI provider error: {exc}"}

    confidence = compute_dual_evidence_confidence(db, organization_id, evidence)
    return {"response_type": "in_channel", "text": f"{answer}\n\n_Confidence: {confidence['confidence']}_"}


def _cmd_hunt(db: Session, organization_id: int, topic: str) -> dict:
    """/sentraops hunt <topic> - semantic search over this org's own
    incidents (not a chat answer, just ranked matches) for open-ended threat
    hunting, e.g. "/sentraops hunt lateral movement"."""
    results = rag_search(db, organization_id, topic, content_type="incident", k=5)
    if not results:
        return {"response_type": "ephemeral", "text": f"No incidents found matching '{topic}'."}

    lines = []
    for r in results:
        if not r["content_id"]:
            continue
        score_pct = round((r["score"] or 0) * 100)
        lines.append(f"- <{FRONTEND_URL}/incidents/{r['content_id']}|incident #{r['content_id']}> ({score_pct}% match)")
    return {"response_type": "in_channel", "text": f"*Found {len(lines)} incident(s) related to '{topic}':*\n" + "\n".join(lines)}


def _cmd_investigate(db: Session, connector: ConnectorInstance, organization_id: int, incident_id_str: str) -> dict:
    try:
        incident_id = int(incident_id_str)
    except ValueError:
        return {"response_type": "ephemeral", "text": f"'{incident_id_str}' isn't a valid incident id."}

    incident = db.query(Incident).filter(Incident.id == incident_id, Incident.organization_id == organization_id).first()
    if not incident:
        return {"response_type": "ephemeral", "text": f"No incident #{incident_id} found in this organization."}

    return _start_investigation(db, connector, incident)


def _start_investigation(db: Session, connector: ConnectorInstance, incident: Incident) -> dict:
    # There's no logged-in user behind a Slack request - attribute the run
    # to whichever admin installed the app for this org, the same pragmatic
    # choice /slack/interactions makes for approve/reject (see main.py).
    installed_by_id = (connector.config or {}).get("installed_by_user_id")
    run = AgentRun(organization_id=incident.organization_id, incident_id=incident.id, triggered_by_id=installed_by_id, status="running")
    db.add(run)
    db.commit()
    db.refresh(run)

    investigate_incident_task.delay(run.id, incident.id)

    return {
        "response_type": "in_channel",
        "text": f"Starting investigation on incident #{incident.id}: {incident.title}. Track progress: {FRONTEND_URL}/incidents/{incident.id}",
    }


def handle_investigate_button(db: Session, team_id: str, incident_id_str: str) -> str:
    """Returns plain text for the button-click response (posted back via
    response_url in main.py) - separate from handle_slash_command because a
    block_actions payload has no "channel didn't say a command" concept."""
    connector = find_connector_by_team_id(db, team_id)
    if not connector:
        return "This Slack workspace isn't connected to a SentraOps organization."
    try:
        incident_id = int(incident_id_str)
    except ValueError:
        return "Invalid incident id."
    incident = db.query(Incident).filter(Incident.id == incident_id, Incident.organization_id == connector.organization_id).first()
    if not incident:
        return f"No incident #{incident_id} found."
    result = _start_investigation(db, connector, incident)
    return result["text"]


def handle_review_action_button(db: Session, team_id: str, value: str, slack_user: str) -> str:
    """Backs the Approve/Reject buttons from notify_proposed_actions - the
    exact same status transition as PATCH /proposed-actions/{id}
    (main.py's review_proposed_action), just triggered from a Slack payload
    instead of an authenticated HTTP request."""
    connector = find_connector_by_team_id(db, team_id)
    if not connector:
        return "This Slack workspace isn't connected to a SentraOps organization."

    try:
        action_id_str, status = value.split(":", 1)
        action_id = int(action_id_str)
    except ValueError:
        return "Malformed button payload."
    if status not in ("approved", "rejected"):
        return "Invalid action status."

    action = (
        db.query(ProposedAction)
        .filter(ProposedAction.id == action_id, ProposedAction.organization_id == connector.organization_id)
        .first()
    )
    if not action:
        return "Proposed action not found."
    if action.status != "pending":
        return f"Action already {action.status}."

    from datetime import datetime, timezone

    action.status = status
    action.reviewed_by_id = (connector.config or {}).get("installed_by_user_id")
    action.reviewed_at = datetime.now(timezone.utc)
    db.commit()

    return f"{status.capitalize()} by {slack_user} in Slack: {action.description}"
