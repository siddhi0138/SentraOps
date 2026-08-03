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

        text = (
            f"[CyberSentinel AI] {action['category'].upper()} action approved "
            f"for incident #{action['incident_id']}: {action['description']}"
        )
        try:
            response = httpx.post(url, json={"text": text, "content": text}, timeout=10)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            return False, f"Webhook POST failed: {exc}"
        return True, f"Webhook POST succeeded ({response.status_code})"
