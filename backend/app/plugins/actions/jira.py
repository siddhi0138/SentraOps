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

    def _lookup_account_id(self, base_url: str, auth: tuple, assignee_email: str) -> str | None:
        """Jira's create-issue API needs the assignee's internal accountId,
        not their email - this is a real lookup against Jira's own user
        directory, not a guess. Returns None (not an error) if the
        incident's assignee isn't a real Jira user - the ticket still gets
        created, just unassigned, rather than failing the whole action over
        a name mismatch between the two systems."""
        try:
            response = httpx.get(
                f"{base_url.rstrip('/')}/rest/api/3/user/search",
                params={"query": assignee_email},
                auth=auth,
                headers={"Accept": "application/json"},
                timeout=15,
            )
            if not response.is_success:
                return None
            users = response.json()
        except httpx.HTTPError:
            return None
        return users[0]["accountId"] if users else None

    def execute(self, config: dict, action: dict) -> tuple[bool, str]:
        base_url = config.get("base_url")
        email = config.get("email")
        api_token = config.get("api_token")
        project_key = config.get("project_key")
        if not all([base_url, email, api_token, project_key]):
            return False, "config.base_url, email, api_token, and project_key are all required"

        incident_title = action.get("incident_title")
        summary = (
            f"[SentraOps] {action['category'].title()} - {incident_title}"
            if incident_title
            else f"[SentraOps] {action['category'].title()} action for incident #{action['incident_id']}"
        )
        description_lines = [action["description"], ""]
        if incident_title:
            description_lines.append(f"Incident: #{action['incident_id']} - {incident_title}")
        if action.get("risk_level"):
            description_lines.append(f"Risk level: {action['risk_level']} (priority: {action.get('priority', 'unknown')})")
        if action.get("affected_hosts"):
            description_lines.append(f"Affected hosts: {', '.join(action['affected_hosts'])}")
        if action.get("affected_users"):
            description_lines.append(f"Affected users: {', '.join(action['affected_users'])}")
        if action.get("incident_url"):
            description_lines.append(f"Details: {action['incident_url']}")

        payload = {
            "fields": {
                "project": {"key": project_key},
                "summary": summary[:255],
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {"type": "paragraph", "content": [{"type": "text", "text": line}]}
                        for line in description_lines
                        if line
                    ],
                },
                "issuetype": {"name": "Task"},
            }
        }

        auth = (email, api_token)
        assignee_email = action.get("assignee_email")
        account_id = self._lookup_account_id(base_url, auth, assignee_email) if assignee_email else None
        if account_id:
            payload["fields"]["assignee"] = {"accountId": account_id}

        try:
            response = httpx.post(
                f"{base_url.rstrip('/')}/rest/api/3/issue",
                json=payload,
                auth=auth,
                timeout=15,
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            return False, f"Jira issue creation failed: {exc}"

        issue_key = response.json().get("key", "?")
        issue_url = f"{base_url.rstrip('/')}/browse/{issue_key}"
        if account_id:
            return True, f"Created Jira issue {issue_key} (assigned to {assignee_email}): {issue_url}"
        if assignee_email:
            return True, f"Created Jira issue {issue_key} (unassigned - no Jira user found for {assignee_email}): {issue_url}"
        return True, f"Created Jira issue {issue_key}: {issue_url}"
