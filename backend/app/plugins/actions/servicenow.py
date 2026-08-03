import httpx

from app.plugins.base import ResponseActionPlugin

_URGENCY_BY_CATEGORY = {"containment": "1", "eradication": "2", "recovery": "3"}


class ServiceNowAction(ResponseActionPlugin):
    """Creates a real ServiceNow incident for an approved response action
    via the Table API (Basic Auth). Same "no paid tenant to permanently
    test against" situation as app/plugins/actions/jira.py - config-driven
    against whichever instance the org's admin points it at."""

    key = "servicenow"
    display_name = "ServiceNow"
    categories = ["containment", "eradication", "recovery"]
    config_fields = ["instance_url", "username", "password"]

    def execute(self, config: dict, action: dict) -> tuple[bool, str]:
        instance_url = config.get("instance_url")
        username = config.get("username")
        password = config.get("password")
        if not all([instance_url, username, password]):
            return False, "config.instance_url, username, and password are all required"

        incident_title = action.get("incident_title")
        short_description = (
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
            "short_description": short_description[:160],
            "description": "\n".join(description_lines).strip(),
            "urgency": _URGENCY_BY_CATEGORY.get(action["category"], "2"),
        }
        try:
            response = httpx.post(
                f"{instance_url.rstrip('/')}/api/now/table/incident",
                json=payload,
                auth=(username, password),
                headers={"Accept": "application/json"},
                timeout=15,
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            return False, f"ServiceNow incident creation failed: {exc}"

        number = response.json().get("result", {}).get("number", "?")
        return True, f"Created ServiceNow incident {number}"
