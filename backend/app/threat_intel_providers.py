import os

import httpx

VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")

VIRUSTOTAL_API = "https://www.virustotal.com/api/v3"
ABUSEIPDB_API = "https://api.abuseipdb.com/api/v2/check"


def _lookup_virustotal(value: str, indicator_type: str) -> dict | None:
    """Real VirusTotal v3 lookup (free tier: 4 req/min, 500/day). Returns
    None on any failure (no key configured, rate limit, network error, not
    found) - the caller falls back to local-only matching, exactly what
    happens today without this module, never raising into correlation."""
    if not VIRUSTOTAL_API_KEY:
        return None
    endpoint = "ip_addresses" if indicator_type == "ip" else "domains"
    try:
        response = httpx.get(
            f"{VIRUSTOTAL_API}/{endpoint}/{value}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=10,
        )
        if not response.is_success:
            return None
        data = response.json()
    except httpx.HTTPError:
        return None

    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) or 1
    if malicious == 0 and suspicious == 0:
        return {"verdict": "VirusTotal: no vendors flagged this as malicious", "confidence": 10, "source": "VirusTotal (Live)"}
    confidence = min(round(100 * (malicious + suspicious * 0.5) / total), 100)
    verdict = f"VirusTotal: {malicious} vendor(s) flagged malicious, {suspicious} suspicious (of {total})"
    return {"verdict": verdict, "confidence": confidence, "source": "VirusTotal (Live)"}


def _lookup_abuseipdb(ip: str) -> dict | None:
    """Real AbuseIPDB lookup (free tier: 1,000 checks/day). IP-only, no
    domain support - matches AbuseIPDB's own API scope."""
    if not ABUSEIPDB_API_KEY:
        return None
    try:
        response = httpx.get(
            ABUSEIPDB_API,
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10,
        )
        if not response.is_success:
            return None
        data = response.json().get("data", {})
    except httpx.HTTPError:
        return None

    score = data.get("abuseConfidenceScore", 0)
    reports = data.get("totalReports", 0)
    verdict = f"AbuseIPDB: {score}% abuse confidence ({reports} report(s) in the last 90 days)"
    return {"verdict": verdict, "confidence": score, "source": "AbuseIPDB (Live)"}


def live_lookup(value: str, indicator_type: str) -> dict | None:
    """Tries a real live lookup for one indicator - VirusTotal first
    (handles both IPs and domains), AbuseIPDB as an IP-only fallback if
    VirusTotal isn't configured or found nothing. Returns None if neither
    is configured, or nothing came back - the caller degrades to whatever
    it would have done without this module (local-indicator-table lookup
    only), never blocking or failing correlation over a third-party API."""
    result = _lookup_virustotal(value, indicator_type)
    if result:
        return result
    if indicator_type == "ip":
        result = _lookup_abuseipdb(value)
        if result:
            return result
    return None
