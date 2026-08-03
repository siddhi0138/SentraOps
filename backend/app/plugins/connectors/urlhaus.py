import csv
from urllib.parse import urlparse

import httpx

from app.plugins.base import ConnectorPlugin

# abuse.ch's JSON API now requires an Auth-Key (account signup), but this
# plaintext CSV dump of the same recent-URLs feed stays genuinely public -
# no key, real live data, not a fixture. Confirmed live against the real
# endpoint while building this connector.
URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"


def fetch_records(limit: int = 50) -> list[dict]:
    """Structured URLhaus records (host/threat/tags/url_status), shared by
    UrlhausConnector.pull() below (event-shaped output for log ingestion)
    and app/threat_intel_hub.py's sync_urlhaus() (indicator-shaped output
    for the Threat Intel Hub) - both need the same underlying real data,
    just reshaped differently."""
    response = httpx.get(URLHAUS_CSV_URL, timeout=15)
    response.raise_for_status()

    rows = (line for line in response.text.splitlines() if line and not line.startswith("#"))
    records = []
    for row in csv.reader(rows):
        if len(row) < 9:
            continue
        _id, date_added, url, url_status, _last_online, threat, tags, urlhaus_link, _reporter = row[:9]
        records.append(
            {
                "date_added": date_added,
                "url": url,
                "host": urlparse(url).hostname or "unknown-threat-host",
                "url_status": url_status,
                "threat": threat,
                "tags": tags,
                "urlhaus_link": urlhaus_link,
            }
        )
    return records[:limit]


class UrlhausConnector(ConnectorPlugin):
    """Pulls currently-tracked malicious URLs from abuse.ch's URLhaus feed.
    Free, keyless, real threat intelligence - one of the two reference
    connectors proving the plugin framework end-to-end without needing any
    external account this project doesn't have."""

    key = "urlhaus"
    display_name = "URLhaus Malware URL Feed"
    category = "threat_intel"
    source_type = "generic"
    config_fields: list[str] = []

    def test_connection(self, config: dict) -> tuple[bool, str]:
        try:
            response = httpx.get(URLHAUS_CSV_URL, timeout=10)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            return False, f"URLhaus request failed: {exc}"
        if "URLhaus" not in response.text[:200]:
            return False, "Unexpected response from URLhaus"
        return True, "Connected to URLhaus"

    def pull(self, config: dict) -> list[dict]:
        records = fetch_records(limit=50)
        return [
            {
                "timestamp": r["date_added"],
                "host": r["host"],
                "event_type": "malicious_url_reported",
                "severity": "high" if r["url_status"] == "online" else "medium",
                "message": f"URLhaus reported {r['url']} as {r['threat']}"
                + (f" (tags: {r['tags']})" if r["tags"] else "")
                + f" - {r['urlhaus_link']}",
            }
            for r in records
        ]
