import httpx

from app.plugins.base import ConnectorPlugin

SLACK_API = "https://slack.com/api"


class SlackConnector(ConnectorPlugin):
    """Installed via OAuth (see app/slack_oauth.py + the /connectors/slack/*
    routes in app/main.py), not typed-in config - by the time test_connection
    or pull run, instance.config already has the bot token the OAuth
    callback stored. This plugin's real job isn't log ingestion (pull()
    deliberately does nothing) - it's the connector-instance row that holds
    the workspace's bot token, reused by app/slack_bot.py to post incident
    alerts and by the /slack/commands + /slack/interactions webhook handlers
    to map an inbound Slack request back to an organization_id."""

    key = "slack"
    display_name = "Slack"
    category = "collaboration"
    source_type = "slack"
    auth_type = "oauth"
    config_fields: list[str] = []

    def test_connection(self, config: dict) -> tuple[bool, str]:
        token = config.get("access_token")
        if not token:
            return False, "Not connected - use 'Connect to Slack' to install the app"
        response = httpx.get(f"{SLACK_API}/auth.test", headers={"Authorization": f"Bearer {token}"}, timeout=10)
        data = response.json()
        if not data.get("ok"):
            return False, data.get("error", "Slack API error")
        return True, f"Connected to workspace '{data.get('team')}' as {data.get('user')}"

    def pull(self, config: dict) -> list[dict]:
        # Deliberately not a log source - see class docstring. Present only
        # to satisfy the ConnectorPlugin interface so this still works with
        # the generic /connectors/{id}/sync button in the UI (a no-op sync).
        return []
