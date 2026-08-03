import json
from pathlib import Path
from unittest.mock import patch

from neo4j.exceptions import ServiceUnavailable

from app.correlation import run_correlation
from app.db_models import Incident
from app.ingestion import ingest
from app.threat_intel_hub import (
    get_indicator_graph,
    indicator_type_of,
    lookup_many,
    resync_indicator_graph,
    search,
    sync_urlhaus,
    upsert_indicator,
)
from tests.test_graph import FakeDriver, FakeNode, FakeRelationship

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"


def test_indicator_type_of_detects_ip_vs_domain():
    assert indicator_type_of("8.8.8.8") == "ip"
    assert indicator_type_of("evil.example.com") == "domain"


def test_upsert_indicator_creates_new_row(db_session):
    row = upsert_indicator(
        db_session, indicator="evil.example.com", indicator_type="domain", verdict="malware", confidence=80, source="test"
    )
    db_session.commit()
    assert row.id is not None
    assert row.indicator == "evil.example.com"


def test_upsert_indicator_updates_existing_case_insensitively(db_session):
    upsert_indicator(db_session, indicator="Evil.Example.com", indicator_type="domain", verdict="v1", confidence=50, source="a")
    db_session.commit()

    updated = upsert_indicator(
        db_session, indicator="evil.example.com", indicator_type="domain", verdict="v2", confidence=90, source="b"
    )
    db_session.commit()

    all_rows = search(db_session, q="evil.example.com")
    assert len(all_rows) == 1
    assert updated.verdict == "v2"
    assert updated.confidence == 90


def test_lookup_many_matches_case_insensitively_and_dedupes(db_session):
    upsert_indicator(db_session, indicator="1.2.3.4", indicator_type="ip", verdict="bad", confidence=70, source="test")
    db_session.commit()

    hits = lookup_many(db_session, ["1.2.3.4", "1.2.3.4", "not-a-match", None])
    assert set(hits.keys()) == {"1.2.3.4"}
    assert hits["1.2.3.4"].verdict == "bad"


def test_search_filters_by_type_and_query(db_session):
    upsert_indicator(db_session, indicator="1.2.3.4", indicator_type="ip", verdict="x", confidence=50, source="t")
    upsert_indicator(db_session, indicator="evil.example.com", indicator_type="domain", verdict="x", confidence=50, source="t")
    db_session.commit()

    # 2, not 1: the migration-seeded demo indicator (185.220.101.45) is
    # also type "ip".
    assert len(search(db_session, indicator_type="ip")) == 2
    assert len(search(db_session, q="evil")) == 1
    assert len(search(db_session)) == 3


def test_sync_urlhaus_upserts_real_shaped_records(db_session):
    fake_records = [
        {
            "date_added": "2026-07-27 00:00:00",
            "url": "http://malicious-host.example/x",
            "host": "malicious-host.example",
            "url_status": "online",
            "threat": "malware_download",
            "tags": "mirai",
            "urlhaus_link": "https://urlhaus.abuse.ch/url/1/",
        }
    ]
    with patch("app.threat_intel_hub.fetch_records", return_value=fake_records):
        count = sync_urlhaus(db_session)

    assert count == 1
    results = search(db_session, q="malicious-host.example")
    assert len(results) == 1
    assert results[0].indicator_type == "domain"
    assert results[0].source == "URLhaus (abuse.ch)"
    assert results[0].confidence == 90  # online -> high confidence


def test_correlation_matches_threat_intel_by_host_not_just_ip(db_session, org_id):
    upsert_indicator(
        db_session, indicator="FINANCE-PC-21", indicator_type="domain", verdict="known-compromised host", confidence=85, source="test"
    )
    db_session.commit()

    ingest(db_session, org_id, "windows", json.loads((SAMPLES / "windows_events.json").read_text()))
    ingest(db_session, org_id, "firewall", json.loads((SAMPLES / "firewall.json").read_text()))
    ingest(db_session, org_id, "syslog", (SAMPLES / "syslog.log").read_text().splitlines())

    incident = run_correlation(db_session, org_id)[0]
    indicators = {ti["indicator"] for ti in incident.threat_intel}
    assert "FINANCE-PC-21" in indicators
    assert "185.220.101.45" in indicators  # the pre-seeded demo indicator still matches too


def test_list_threat_indicators_endpoint(client, viewer_headers):
    response = client.get("/threat-intel/indicators", headers=viewer_headers)
    assert response.status_code == 200
    indicators = response.json()["indicators"]
    assert any(i["indicator"] == "185.220.101.45" for i in indicators)


def test_list_threat_indicators_filters(client, viewer_headers, db_session):
    upsert_indicator(db_session, indicator="evil.example.com", indicator_type="domain", verdict="x", confidence=50, source="t")
    db_session.commit()

    response = client.get("/threat-intel/indicators", params={"q": "185.220"}, headers=viewer_headers)
    assert response.status_code == 200
    assert len(response.json()["indicators"]) == 1

    response = client.get("/threat-intel/indicators", params={"indicator_type": "domain"}, headers=viewer_headers)
    assert response.status_code == 200
    domain_results = response.json()["indicators"]
    assert len(domain_results) == 1
    assert domain_results[0]["indicator"] == "evil.example.com"


def test_sync_threat_intel_requires_analyst_or_admin(client, viewer_headers, analyst_headers):
    with patch("app.main.sync_urlhaus", return_value=5):
        assert client.post("/threat-intel/sync", headers=viewer_headers).status_code == 403
        response = client.post("/threat-intel/sync", headers=analyst_headers)
    assert response.status_code == 200
    assert response.json() == {"synced": 5}


def test_sync_threat_intel_reports_upstream_failure_cleanly(client, analyst_headers):
    with patch("app.main.sync_urlhaus", side_effect=RuntimeError("feed unreachable")):
        response = client.post("/threat-intel/sync", headers=analyst_headers)
    assert response.status_code == 502


def test_threat_intel_endpoints_require_authentication(client):
    assert client.get("/threat-intel/indicators").status_code == 401
    assert client.post("/threat-intel/sync").status_code == 401


def test_resync_indicator_graph_builds_indicator_and_tag_rows(db_session):
    # The migration seeds one demo indicator (185.220.101.45) platform-wide
    # since ThreatIndicator isn't org-scoped - every fresh test/dev/prod
    # database already has it (same fixture this project's own compliance
    # tests already had to account for once). Assert on the two indicators
    # added here being *present*, not on an isolated total count.
    upsert_indicator(
        db_session, indicator="evil.example.com", indicator_type="domain",
        verdict="malware_download", confidence=90, source="URLhaus", tags="mirai, botnet",
    )
    upsert_indicator(
        db_session, indicator="1.2.3.4", indicator_type="ip",
        verdict="c2", confidence=70, source="URLhaus", tags=None,
    )
    db_session.commit()

    fake_driver = FakeDriver()
    stats = resync_indicator_graph(db_session, driver=fake_driver)

    assert stats["indicators"] == 3  # the two added here + the migration-seeded demo indicator
    # mirai + botnet from the indicator added here, plus tor + c2 from the
    # migration-seeded demo indicator (which also carries real tags).
    assert stats["tag_links"] == 4

    fn, args = fake_driver.fake_session.write_calls[0]
    assert fn.__name__ == "_rebuild_indicator_graph_tx"
    indicator_rows, tag_edges, match_rows = args
    values = {row["value"] for row in indicator_rows}
    assert {"evil.example.com", "1.2.3.4"}.issubset(values)
    tags = {edge["tag"] for edge in tag_edges}
    assert {"mirai", "botnet"}.issubset(tags)
    assert match_rows == []


def test_resync_indicator_graph_extracts_real_incident_matches(db_session, org_id):
    upsert_indicator(
        db_session, indicator="185.220.101.45", indicator_type="ip",
        verdict="tor exit node", confidence=95, source="demo", tags=None,
    )
    db_session.add(
        Incident(
            organization_id=org_id,
            title="Test incident",
            confidence=90,
            risk_score=80,
            risk_level="high",
            threat_intel=[{"indicator": "185.220.101.45", "indicator_type": "ip", "verdict": "x", "confidence": 90, "source": "demo"}],
        )
    )
    db_session.commit()

    fake_driver = FakeDriver()
    stats = resync_indicator_graph(db_session, driver=fake_driver)

    assert stats["incident_matches"] == 1
    fn, args = fake_driver.fake_session.write_calls[0]
    _, _, match_rows = args
    assert match_rows[0]["value"] == "185.220.101.45"


def test_get_indicator_graph_processes_result():
    indicator = FakeNode("Indicator", {"value": "evil.example.com", "indicator_type": "domain", "verdict": "v", "confidence": 90, "source": "URLhaus"})
    tag = FakeNode("Tag", {"name": "mirai"})
    fake_driver = FakeDriver(run_result=[{"a": indicator, "r": FakeRelationship("TAGGED_AS"), "b": tag}])

    result = get_indicator_graph(organization_id=1, driver=fake_driver)

    assert len(result["nodes"]) == 2
    keys = {n["key"] for n in result["nodes"]}
    assert keys == {"Indicator:evil.example.com", "Tag:mirai"}
    assert result["edges"][0]["type"] == "TAGGED_AS"


def test_threat_intel_graph_sync_endpoint(client, analyst_headers):
    with patch("app.main.resync_indicator_graph", return_value={"indicators": 3, "tag_links": 2, "incident_matches": 1}):
        response = client.post("/threat-intel/graph/sync", headers=analyst_headers)
    assert response.status_code == 200
    assert response.json() == {"indicators": 3, "tag_links": 2, "incident_matches": 1}


def test_threat_intel_graph_endpoint(client, viewer_headers):
    with patch("app.main.get_indicator_graph", return_value={"nodes": [], "edges": []}):
        response = client.get("/threat-intel/graph", headers=viewer_headers)
    assert response.status_code == 200
    assert response.json() == {"nodes": [], "edges": []}


def test_threat_intel_graph_returns_503_when_neo4j_unavailable(client, viewer_headers):
    with patch("app.main.get_indicator_graph", side_effect=ServiceUnavailable("down")):
        response = client.get("/threat-intel/graph", headers=viewer_headers)
    assert response.status_code == 503


def test_threat_intel_graph_endpoints_require_authentication(client):
    assert client.get("/threat-intel/graph").status_code == 401
    assert client.post("/threat-intel/graph/sync").status_code == 401
