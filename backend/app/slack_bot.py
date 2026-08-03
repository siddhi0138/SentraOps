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


def send_report_to_slack(db: Session, incident: Incident) -> tuple[bool, str]:
    """Backs the Download Report button's "also send to Slack" behavior -
    uploads incident.report as a real .md file into the org's default
    channel via Slack's three-step external-upload flow (getUploadURLExternal
    -> upload the bytes -> completeUploadExternal), the current recommended
    way to share a file (the older files.upload endpoint is deprecated).
    Needs the files:write scope - an org that installed Slack before this
    scope existed will need to reinstall before this works, same as
    chat:write.public was needed before critical-channel routing worked."""
    connector = get_org_slack_connector(db, incident.organization_id)
    if not connector:
        return False, "Slack isn't connected for this organization"
    config = connector.config or {}
    token = config.get("access_token")
    channel_id = config.get("channel_id")
    if not token or not channel_id:
        return False, "Slack isn't fully configured for this organization"

    content = (incident.report or "").encode("utf-8")
    filename = f"incident-{incident.id}-report.md"
    headers = {"Authorization": f"Bearer {token}"}

    try:
        url_resp = httpx.post(
            f"{SLACK_API}/files.getUploadURLExternal",
            headers=headers,
            data={"filename": filename, "length": len(content)},
            timeout=15,
        )
        url_data = url_resp.json()
        if not url_data.get("ok"):
            return False, f"Slack rejected the upload request: {url_data.get('error', 'unknown error')}"

        upload_resp = httpx.post(url_data["upload_url"], files={"file": (filename, content)}, timeout=30)
        if not upload_resp.is_success:
            return False, f"Slack file upload failed (HTTP {upload_resp.status_code})"

        complete_resp = httpx.post(
            f"{SLACK_API}/files.completeUploadExternal",
            headers=headers,
            json={
                "files": [{"id": url_data["file_id"], "title": f"Incident #{incident.id} report"}],
                "channel_id": channel_id,
                "initial_comment": f"Report for incident #{incident.id}: {incident.title}",
            },
            timeout=15,
        )
        complete_data = complete_resp.json()
        if not complete_data.get("ok"):
            return False, f"Slack rejected finalizing the upload: {complete_data.get('error', 'unknown error')}"
    except httpx.HTTPError as exc:
        return False, f"Slack upload failed: {exc}"

    return True, "Report sent to Slack"


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


# The four secondary-channel roles an org can optionally name, beyond the
# one default channel every install already has (the incoming-webhook
# channel picked on Slack's consent screen). Each is a plain channel-name
# string in connector.config, e.g. {"soc_team_channel": "soc-team"} - see
# PATCH /connectors/{id}. Matches the #security-alerts (default) /
# #critical-incidents / #soc-team / #executive-security / #compliance
# channel-per-purpose pattern real SOC teams actually use, without forcing
# every org to create all five - anything left unset just falls back to
# the one default channel.
CRITICAL_CHANNEL = "critical_channel"
SOC_TEAM_CHANNEL = "soc_team_channel"
EXECUTIVE_CHANNEL = "executive_channel"
COMPLIANCE_CHANNEL = "compliance_channel"

_DEFAULT_CHANNEL_NAMES = {
    CRITICAL_CHANNEL: "critical-incidents",
    SOC_TEAM_CHANNEL: "soc-team",
    EXECUTIVE_CHANNEL: "executive-security",
    COMPLIANCE_CHANNEL: "compliance",
}


def _create_or_find_channel(token: str, name: str) -> str | None:
    """Creates a public channel via conversations.create - if it already
    exists (Slack returns error "name_taken", e.g. a re-install, or two
    orgs on the same workspace during testing), falls back to looking it up
    instead of failing, so this is safe to call more than once."""
    try:
        response = httpx.post(
            f"{SLACK_API}/conversations.create",
            headers={"Authorization": f"Bearer {token}"},
            data={"name": name, "is_private": "false"},
            timeout=15,
        )
        data = response.json()
    except httpx.HTTPError:
        return None
    if data.get("ok"):
        return data["channel"]["id"]
    if data.get("error") == "name_taken":
        return _resolve_channel_id(token, name)
    return None


def provision_default_channels(token: str) -> dict:
    """Fired once, right after a fresh OAuth install (see slack_callback in
    main.py) - auto-creates the four optional secondary channels
    (critical-incidents / soc-team / executive-security / compliance) so
    every org gets a fully working multi-channel setup with zero manual
    setup, instead of the admin having to create each channel by hand and
    fill in a form (PATCH /connectors/{id} still lets them rename any of
    these to point at their own existing channels instead, later). Best
    effort per channel - a failure to create/find one just leaves that role
    unset, falling back to the default channel, never blocking the install
    itself."""
    config: dict[str, str] = {}
    for channel_key, channel_name in _DEFAULT_CHANNEL_NAMES.items():
        channel_id = _create_or_find_channel(token, channel_name)
        if channel_id:
            config[channel_key] = channel_name
            config[f"{channel_key}_id"] = channel_id
    return config


def _post_to_named_channel(db: Session, connector: ConnectorInstance, channel_key: str, blocks: list[dict], text: str) -> bool:
    """Posts to one org-configured secondary channel (channel_key is one of
    the *_CHANNEL constants above) via chat.postMessage - resolves the
    channel name to an id via conversations.list once, then caches it under
    "{channel_key}_id" so every later post skips the lookup (PATCH
    /connectors/{id} clears the cached id whenever the name changes).
    Returns False (not an exception) for "nothing configured" or "couldn't
    resolve/post", so callers can fall back to the default channel."""
    config = connector.config or {}
    channel_name = config.get(channel_key)
    token = config.get("access_token")
    if not channel_name or not token:
        return False

    cache_key = f"{channel_key}_id"
    channel_id = config.get(cache_key)
    if not channel_id:
        channel_id = _resolve_channel_id(token, channel_name)
        if not channel_id:
            return False
        connector.config = {**config, cache_key: channel_id}
        db.commit()

    return _post_to_channel(token, channel_id, blocks, text)


def _post_to_channel_or_default(db: Session, connector: ConnectorInstance, channel_key: str, blocks: list[dict], text: str) -> None:
    """For message types that have exactly one home (unlike the new-incident
    alert, which always goes to the default channel *and* optionally also
    to critical_channel) - posts to the named secondary channel if the org
    configured one, otherwise falls back to the one default channel, so
    orgs that haven't set up channel routing still get every message
    somewhere, not silently nowhere."""
    if _post_to_named_channel(db, connector, channel_key, blocks, text):
        return
    webhook_url = (connector.config or {}).get("incoming_webhook_url")
    if not webhook_url:
        return
    try:
        _post_message(webhook_url, blocks, text)
    except httpx.HTTPError:
        pass


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

    if incident.risk_level == "critical":
        _post_to_named_channel(db, connector, CRITICAL_CHANNEL, blocks, text)


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

    incident_url = f"{FRONTEND_URL}/incidents/{incident.id}"
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
        _post_to_channel_or_default(
            db, connector, SOC_TEAM_CHANNEL, blocks, text=f"Proposed action for incident #{incident.id}: {action.description}"
        )


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

    display_name = _AGENT_DISPLAY_NAMES.get(agent_name, agent_name.replace("_", " ").title())
    incident_url = f"{FRONTEND_URL}/incidents/{incident.id}"
    text = f"*{display_name}* completed for <{incident_url}|incident #{incident.id}>"
    if message:
        text += f"\n{message[:400]}"
    _post_to_channel_or_default(db, connector, SOC_TEAM_CHANNEL, [{"type": "section", "text": {"type": "mrkdwn", "text": text}}], text)


def notify_run_failed(db: Session, run: AgentRun, incident: Incident, error: str | None) -> None:
    connector = get_org_slack_connector(db, run.organization_id)
    if not connector:
        return

    incident_url = f"{FRONTEND_URL}/incidents/{incident.id}"
    text = f":warning: Investigation failed for <{incident_url}|incident #{incident.id}>: {error or 'unknown error'}"
    _post_to_channel_or_default(db, connector, SOC_TEAM_CHANNEL, [{"type": "section", "text": {"type": "mrkdwn", "text": text}}], text)


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


def notify_compliance_report(db: Session, organization_id: int, report: dict) -> None:
    """Fired when someone generates a compliance report (POST
    /compliance/report in main.py) - routed to compliance_channel if the org
    configured one, otherwise the default channel. A no-op, not an error, if
    Slack isn't connected at all - report generation must never depend on
    Slack being set up."""
    connector = get_org_slack_connector(db, organization_id)
    if not connector:
        return

    text = f"*Compliance report ready*\n*Posture:* {report.get('overall_posture', 'unknown')}\n{report.get('summary', '')}"
    _post_to_channel_or_default(db, connector, COMPLIANCE_CHANNEL, [{"type": "section", "text": {"type": "mrkdwn", "text": text}}], text)


def notify_assignment(db: Session, incident: Incident, assignee: User) -> None:
    """Fired when an incident is assigned to someone (PATCH
    /incidents/{id} in main.py) - mirrors the in-app Notification that
    endpoint already creates, just surfaced in Slack too. Routed to
    soc_team_channel (workflow noise, same bucket as investigation
    progress/approvals), falling back to the default channel."""
    connector = get_org_slack_connector(db, incident.organization_id)
    if not connector:
        return
    incident_url = f"{FRONTEND_URL}/incidents/{incident.id}"
    text = f"*{assignee.email}* was assigned <{incident_url}|incident #{incident.id}: {incident.title}>"
    _post_to_channel_or_default(db, connector, SOC_TEAM_CHANNEL, [{"type": "section", "text": {"type": "mrkdwn", "text": text}}], text)


def notify_status_change(db: Session, incident: Incident, actor: User, old_status: str, new_status: str) -> None:
    """Fired when an incident's status actually changes (PATCH
    /incidents/{id}) - not fired for a PATCH that touches priority/assignee
    only, or one that sets status to the value it already had."""
    connector = get_org_slack_connector(db, incident.organization_id)
    if not connector:
        return
    incident_url = f"{FRONTEND_URL}/incidents/{incident.id}"
    text = f"*{actor.email}* changed <{incident_url}|incident #{incident.id}> status: *{old_status}* -> *{new_status}*"
    _post_to_channel_or_default(db, connector, SOC_TEAM_CHANNEL, [{"type": "section", "text": {"type": "mrkdwn", "text": text}}], text)


def notify_comment(db: Session, incident: Incident, author: User, body: str) -> None:
    """Fired when someone comments on an incident (POST
    /incidents/{id}/comments)."""
    connector = get_org_slack_connector(db, incident.organization_id)
    if not connector:
        return
    incident_url = f"{FRONTEND_URL}/incidents/{incident.id}"
    text = f"*{author.email}* commented on <{incident_url}|incident #{incident.id}>:\n> {body[:300]}"
    _post_to_channel_or_default(db, connector, SOC_TEAM_CHANNEL, [{"type": "section", "text": {"type": "mrkdwn", "text": text}}], text)


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
        if not (connector.config or {}).get("incoming_webhook_url"):
            continue
        summary = get_summary(db, connector.organization_id)
        try:
            briefing = generate_briefing(summary)
        except (ChatConfigError, ChatProviderError):
            continue
        text = f"*Daily SentraOps Summary*\n*{briefing['headline']}*\n{briefing['summary']}"
        _post_to_channel_or_default(db, connector, EXECUTIVE_CHANNEL, [{"type": "section", "text": {"type": "mrkdwn", "text": text}}], text)


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
