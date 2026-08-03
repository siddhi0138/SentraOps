import httpx

from app.plugins.base import ConnectorPlugin

GITHUB_API = "https://api.github.com"

# Only these event types are meaningfully security-relevant for a repo
# (access/visibility changes) - everything else maps to "low" so the
# connector still ingests a full real activity stream instead of silently
# dropping event types it doesn't recognize.
SECURITY_SEVERITY = {
    "MemberEvent": "high",  # collaborator added/removed/permission changed
    "PublicEvent": "high",  # repo made public
    "DeleteEvent": "medium",  # branch/tag deleted
}


class GitHubEventsConnector(ConnectorPlugin):
    """Pulls a public GitHub repository's real activity feed. No auth
    needed for public repos (GitHub rate-limits unauthenticated requests to
    60/hour/IP, which is fine for a demo connector) - config just names
    which repo to watch, proving the plugin framework's per-instance config
    works, not just keyless zero-config connectors like URLhaus."""

    key = "github_events"
    display_name = "GitHub Repository Activity"
    category = "cloud"
    source_type = "generic"
    config_fields = ["repo"]  # "owner/name"

    def test_connection(self, config: dict) -> tuple[bool, str]:
        repo = config.get("repo", "")
        if "/" not in repo:
            return False, "config.repo must be 'owner/name'"
        try:
            response = httpx.get(f"{GITHUB_API}/repos/{repo}", timeout=10)
        except httpx.HTTPError as exc:
            return False, f"GitHub request failed: {exc}"
        if response.status_code == 404:
            return False, f"Repository '{repo}' not found (or private)"
        if not response.is_success:
            return False, f"GitHub returned {response.status_code}"
        return True, f"Connected to {repo}"

    def pull(self, config: dict) -> list[dict]:
        repo = config["repo"]
        response = httpx.get(f"{GITHUB_API}/repos/{repo}/events", params={"per_page": 30}, timeout=15)
        response.raise_for_status()

        items = []
        for entry in response.json():
            event_type = entry.get("type", "unknown")
            actor = (entry.get("actor") or {}).get("login", "unknown")
            items.append(
                {
                    "timestamp": entry.get("created_at"),
                    "host": repo,
                    "username": actor,
                    "event_type": f"github_{event_type.lower()}",
                    "severity": SECURITY_SEVERITY.get(event_type, "low"),
                    "message": f"{actor} triggered {event_type} on {repo}",
                }
            )
        return items
