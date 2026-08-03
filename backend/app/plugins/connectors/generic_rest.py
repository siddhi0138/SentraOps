import json
from datetime import datetime, timezone

import httpx

from app.plugins.base import ConnectorPlugin

DEFAULT_EVENT_TYPE = "generic_event"
DEFAULT_SEVERITY = "medium"
KNOWN_SEVERITIES = {"low", "medium", "high", "critical"}


def _get_path(data, path: str):
    """Dot-path lookup into a parsed JSON response, e.g. "data.events" ->
    data["data"]["events"]. Empty path means the response itself is the
    array/object to read from."""
    if not path:
        return data
    node = data
    for part in path.split("."):
        if isinstance(node, dict):
            node = node.get(part)
        else:
            return None
    return node


def _normalize_severity(raw) -> str:
    if not raw:
        return DEFAULT_SEVERITY
    value = str(raw).strip().lower()
    return value if value in KNOWN_SEVERITIES else DEFAULT_SEVERITY


def _stringify(value):
    """Every field in this platform's Event schema is a plain string (or
    None) - a vendor's own JSON is under no such obligation (confirmed
    live: a real API mapped a field to a JSON integer, which crashed
    ingestion.py's asset upsert on the first `.lower()` call downstream).
    Coerce anything non-None/non-string to its string form here, once,
    rather than trusting every caller downstream to guard against it."""
    if value is None or isinstance(value, str):
        return value
    return str(value)


class GenericRestConnector(ConnectorPlugin):
    """A config-driven connector for any vendor system that exposes a JSON
    REST API - the honest alternative to hand-writing bespoke integrations
    for every named enterprise vendor (AWS CloudTrail, Azure Sentinel,
    Okta, CrowdStrike, Splunk, and the rest of the M4 spec's connector
    list) this project has no paid account to genuinely test against. A
    real customer with real credentials for any such system points this at
    their own endpoint and describes their API's field names via
    `field_map` - the platform never fakes a vendor-specific response or
    pretends to natively speak a vendor's SDK.

    Maps onto the conceptual "authenticate / fetch_events / normalize /
    health_check / disconnect" connector lifecycle within this app's
    existing two-method ConnectorPlugin interface: authenticate = the
    configured auth header, applied on every request; fetch_events = the
    HTTP GET itself; normalize = the field_map/severity_map-driven
    reshaping into this platform's Event schema; health_check =
    test_connection(); disconnect = a deliberate no-op, since this
    connector is stateless per-call (a plain HTTPS GET), not a persistent
    session needing explicit teardown."""

    key = "generic_rest"
    display_name = "Generic REST API Connector"
    category = "custom"
    source_type = "generic"
    config_fields = ["base_url", "auth_header_name", "auth_header_value", "events_json_path", "field_map", "severity_map"]

    def _headers(self, config: dict) -> dict:
        headers = {"Accept": "application/json"}
        name, value = config.get("auth_header_name"), config.get("auth_header_value")
        if name and value:
            headers[name] = value
        return headers

    def test_connection(self, config: dict) -> tuple[bool, str]:
        base_url = config.get("base_url")
        if not base_url:
            return False, "base_url is required"
        try:
            response = httpx.get(base_url, headers=self._headers(config), timeout=10)
        except httpx.HTTPError as exc:
            return False, f"Request failed: {exc}"
        if response.status_code >= 400:
            return False, f"Endpoint returned HTTP {response.status_code}"
        return True, f"Connected to {base_url} (HTTP {response.status_code})"

    def pull(self, config: dict) -> list[dict]:
        base_url = config.get("base_url")
        if not base_url:
            raise ValueError("base_url is required")

        response = httpx.get(base_url, headers=self._headers(config), timeout=15)
        response.raise_for_status()
        payload = response.json()

        items = _get_path(payload, config.get("events_json_path", "")) or []
        if not isinstance(items, list):
            raise ValueError(f"events_json_path '{config.get('events_json_path')}' did not resolve to a list")

        field_map: dict = json.loads(config["field_map"]) if config.get("field_map") else {}
        severity_map: dict = json.loads(config["severity_map"]) if config.get("severity_map") else {}

        def field(item: dict, our_name: str):
            # Not _get_path: an empty/unmapped field_map entry must mean
            # "this field wasn't provided" (None), not "return the whole
            # item" - _get_path's empty-path-means-the-whole-thing rule is
            # correct for events_json_path (an unwrapped top-level array)
            # but wrong here, confirmed by actually pulling a real API and
            # getting the whole record back for every unmapped field.
            path = field_map.get(our_name)
            if not path:
                return None
            return _stringify(_get_path(item, path))

        normalized = []
        for item in items:
            if not isinstance(item, dict):
                continue
            raw_severity = field(item, "severity")
            mapped_severity = severity_map.get(str(raw_severity).lower()) if raw_severity else None

            normalized.append(
                {
                    "timestamp": field(item, "timestamp") or datetime.now(timezone.utc).isoformat(),
                    "host": field(item, "host") or "unknown-host",
                    "username": field(item, "username"),
                    "source_ip": field(item, "source_ip"),
                    "event_type": field(item, "event_type") or DEFAULT_EVENT_TYPE,
                    "severity": _normalize_severity(mapped_severity or raw_severity),
                    "message": field(item, "message") or json.dumps(item)[:500],
                }
            )
        return normalized
