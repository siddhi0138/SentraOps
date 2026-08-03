from unittest.mock import patch

import httpx

from app import threat_intel_providers as providers


def _response(url: str, status_code: int, json_body: dict) -> httpx.Response:
    request = httpx.Request("GET", url)
    return httpx.Response(status_code, json=json_body, request=request)


VT_MALICIOUS_RESPONSE = {
    "data": {"attributes": {"last_analysis_stats": {"malicious": 8, "suspicious": 2, "harmless": 60, "undetected": 10}}}
}
VT_CLEAN_RESPONSE = {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 10}}}}


def test_lookup_virustotal_returns_none_without_api_key(monkeypatch):
    monkeypatch.setattr(providers, "VIRUSTOTAL_API_KEY", "")
    assert providers._lookup_virustotal("1.2.3.4", "ip") is None


def test_lookup_virustotal_flags_malicious_ip(monkeypatch):
    monkeypatch.setattr(providers, "VIRUSTOTAL_API_KEY", "fake-key")
    with patch("app.threat_intel_providers.httpx.get", return_value=_response("x", 200, VT_MALICIOUS_RESPONSE)) as mock_get:
        result = providers._lookup_virustotal("1.2.3.4", "ip")

    assert result is not None
    assert result["source"] == "VirusTotal (Live)"
    assert result["confidence"] > 10
    assert "8 vendor" in result["verdict"]
    assert "ip_addresses/1.2.3.4" in mock_get.call_args.args[0]


def test_lookup_virustotal_uses_domains_endpoint_for_domains(monkeypatch):
    monkeypatch.setattr(providers, "VIRUSTOTAL_API_KEY", "fake-key")
    with patch("app.threat_intel_providers.httpx.get", return_value=_response("x", 200, VT_CLEAN_RESPONSE)) as mock_get:
        providers._lookup_virustotal("evil-domain.com", "domain")

    assert "domains/evil-domain.com" in mock_get.call_args.args[0]


def test_lookup_virustotal_low_confidence_when_clean(monkeypatch):
    monkeypatch.setattr(providers, "VIRUSTOTAL_API_KEY", "fake-key")
    with patch("app.threat_intel_providers.httpx.get", return_value=_response("x", 200, VT_CLEAN_RESPONSE)):
        result = providers._lookup_virustotal("clean.example.com", "domain")

    assert result["confidence"] == 10


def test_lookup_virustotal_returns_none_on_http_error(monkeypatch):
    monkeypatch.setattr(providers, "VIRUSTOTAL_API_KEY", "fake-key")
    with patch("app.threat_intel_providers.httpx.get", side_effect=httpx.ConnectError("unreachable")):
        assert providers._lookup_virustotal("1.2.3.4", "ip") is None


def test_lookup_virustotal_returns_none_on_non_success_status(monkeypatch):
    monkeypatch.setattr(providers, "VIRUSTOTAL_API_KEY", "fake-key")
    with patch("app.threat_intel_providers.httpx.get", return_value=_response("x", 404, {})):
        assert providers._lookup_virustotal("notfound.example.com", "domain") is None


def test_lookup_abuseipdb_returns_none_without_api_key(monkeypatch):
    monkeypatch.setattr(providers, "ABUSEIPDB_API_KEY", "")
    assert providers._lookup_abuseipdb("1.2.3.4") is None


def test_lookup_abuseipdb_reports_confidence_score(monkeypatch):
    monkeypatch.setattr(providers, "ABUSEIPDB_API_KEY", "fake-key")
    body = {"data": {"abuseConfidenceScore": 97, "totalReports": 42}}
    with patch("app.threat_intel_providers.httpx.get", return_value=_response("x", 200, body)):
        result = providers._lookup_abuseipdb("185.220.101.45")

    assert result["source"] == "AbuseIPDB (Live)"
    assert result["confidence"] == 97
    assert "97%" in result["verdict"]
    assert "42 report" in result["verdict"]


def test_live_lookup_prefers_virustotal_over_abuseipdb(monkeypatch):
    monkeypatch.setattr(providers, "VIRUSTOTAL_API_KEY", "fake-vt")
    monkeypatch.setattr(providers, "ABUSEIPDB_API_KEY", "fake-abuse")
    with patch("app.threat_intel_providers.httpx.get", return_value=_response("x", 200, VT_MALICIOUS_RESPONSE)) as mock_get:
        result = providers.live_lookup("1.2.3.4", "ip")

    assert result["source"] == "VirusTotal (Live)"
    mock_get.assert_called_once()  # AbuseIPDB never called since VT already answered


def test_live_lookup_falls_back_to_abuseipdb_for_ips(monkeypatch):
    monkeypatch.setattr(providers, "VIRUSTOTAL_API_KEY", "")
    monkeypatch.setattr(providers, "ABUSEIPDB_API_KEY", "fake-abuse")
    body = {"data": {"abuseConfidenceScore": 55, "totalReports": 3}}
    with patch("app.threat_intel_providers.httpx.get", return_value=_response("x", 200, body)):
        result = providers.live_lookup("1.2.3.4", "ip")

    assert result["source"] == "AbuseIPDB (Live)"


def test_live_lookup_does_not_try_abuseipdb_for_domains(monkeypatch):
    monkeypatch.setattr(providers, "VIRUSTOTAL_API_KEY", "")
    monkeypatch.setattr(providers, "ABUSEIPDB_API_KEY", "fake-abuse")
    result = providers.live_lookup("evil-domain.com", "domain")
    assert result is None


def test_live_lookup_returns_none_when_nothing_configured(monkeypatch):
    monkeypatch.setattr(providers, "VIRUSTOTAL_API_KEY", "")
    monkeypatch.setattr(providers, "ABUSEIPDB_API_KEY", "")
    assert providers.live_lookup("1.2.3.4", "ip") is None
