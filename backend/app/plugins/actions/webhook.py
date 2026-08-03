import httpx

from app.plugins.base import ResponseActionPlugin


class WebhookAction(ResponseActionPlugin):
    """Executes an approved response action by POSTing it to an
    org-configured outbound webhook (Slack incoming webhook, Discord
    webhook, or any generic JSON receiver). This is the one response
    action honestly buildable without a real EDR/firewall/AD environment
    to act against: it notifies a real external system rather than
    pretending to remotely disable an account or block traffic on
    infrastructure this project has no access to."""

    key = "webhook"
    display_name = "Outbound Webhook (Slack / Discord / generic)"
    categories = ["containment", "eradication", "recovery"]
    config_fields = ["webhook_url"]

    def execute(self, config: dict, action: dict) -> tuple[bool, str]:
        url = config.get("webhook_url")
        if not url:
            return False, "config.webhook_url is required"

        incident_title = action.get("incident_title")
        header = (
            f"[SentraOps] {action['category'].upper()} approved - {incident_title}"
            if incident_title
            else f"[SentraOps] {action['category'].upper()} action approved for incident #{action['incident_id']}"
        )
        detail_lines = [action["description"]]
        if action.get("risk_level"):
            detail_lines.append(f"Risk: {action['risk_level']} ({action.get('priority', 'unknown')} priority)")
        if action.get("affected_hosts"):
            detail_lines.append(f"Hosts: {', '.join(action['affected_hosts'])}")
        if action.get("affected_users"):
            detail_lines.append(f"Users: {', '.join(action['affected_users'])}")

        # `content`/`text` (plain, Discord-flavored) works everywhere as a
        # fallback; `blocks` (Slack mrkdwn) is an extra key Slack renders
        # richly and Discord/generic receivers simply ignore.
        incident_url = action.get("incident_url")
        plain_text = "\n".join([header, *detail_lines, incident_url] if incident_url else [header, *detail_lines])
        slack_header = f"*{header}*" if not incident_url else f"*<{incident_url}|{header}>*"
        blocks = [
            {"type": "section", "text": {"type": "mrkdwn", "text": slack_header}},
            {"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(detail_lines)}},
        ]

        try:
            response = httpx.post(url, json={"text": plain_text, "content": plain_text, "blocks": blocks}, timeout=10)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            return False, f"Webhook POST failed: {exc}"
        return True, f"Webhook POST succeeded ({response.status_code})"
