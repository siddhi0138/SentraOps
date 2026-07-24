from app.models import Alert, ThreatIntelMatch

# Mock feed standing in for VirusTotal / AbuseIPDB until milestone 2 wires up
# real lookups.
KNOWN_BAD_IPS = {
    "185.220.101.45": ("known Tor exit node / ransomware C2 infrastructure", 98, "AbuseIPDB (mock)"),
}


class ThreatIntelAgent:
    """Enriches alerts with external threat intelligence context."""

    def run(self, alerts: list[Alert]) -> list[ThreatIntelMatch]:
        matches: list[ThreatIntelMatch] = []
        seen_ips: set[str] = set()

        for alert in alerts:
            ip = alert.event.source_ip
            if ip and ip not in seen_ips and ip in KNOWN_BAD_IPS:
                verdict, confidence, source = KNOWN_BAD_IPS[ip]
                matches.append(ThreatIntelMatch(
                    indicator=ip,
                    indicator_type="ip",
                    verdict=verdict,
                    confidence=confidence,
                    source=source,
                ))
                seen_ips.add(ip)

        return matches
