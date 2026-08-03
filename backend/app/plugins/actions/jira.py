import httpx

from app.plugins.base import ResponseActionPlugin


class JiraAction(ResponseActionPlugin):
    """Creates a real Jira issue for an approved response action via Jira
    Cloud's REST API (Basic Auth: account email + API token - Jira Cloud's
    standard auth scheme, no separate OAuth app needed). Like
    generic_rest.py, this project has no paid Jira instance to permanently
    test against, so it's config-driven against whichever instance the
    org's admin points it at, not hardcoded to a demo tenant."""

    key = "jira"
    display_name = "Jira"
    categories = ["containment", "eradication", "recovery"]
    config_fields = ["base_url", "email", "api_token", "project_key"]

    def execute(self, config: dict, action: dict) -> tuple[bool, str]:
        base_url = config.get("base_url")
        email = config.get("email")
        api_token = config.get("api_token")
        project_key = config.get("project_key")
        if not all([base_url, email, api_token, project_key]):
            return False, "config.base_url, email, api_token, and project_key are all required"

        summary = f"[SentraOps] {action['category'].title()} action for incident #{action['incident_id']}"
        payload = {
            "fields": {
                "project": {"key": project_key},
                "summary": summary[:255],
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [{"type": "paragraph", "content": [{"type": "text", "text": action["description"]}]}],
                },
                "issuetype": {"name": "Task"},
            }
        }
        try:
            response = httpx.post(
                f"{base_url.rstrip('/')}/rest/api/3/issue",
                json=payload,
                auth=(email, api_token),
                timeout=15,
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            return False, f"Jira issue creation failed: {exc}"

        issue_key = response.json().get("key", "?")
        return True, f"Created Jira issue {issue_key}: {base_url.rstrip('/')}/browse/{issue_key}"
