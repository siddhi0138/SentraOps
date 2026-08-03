from app.rag import search, store_embedding


def test_store_and_search_finds_semantically_similar_text(db_session, org_id):
    store_embedding(db_session, org_id, "event", 1, "Failed login attempt for user admin from a suspicious IP address")
    store_embedding(db_session, org_id, "event", 2, "Quarterly sales report generated for the finance department")
    db_session.commit()

    results = search(db_session, org_id, "brute force attack on admin account", k=5)

    assert len(results) == 2
    # the login-failure text should rank above the unrelated sales report
    assert "Failed login" in results[0]["text"]


def test_search_respects_content_type_filter(db_session, org_id):
    store_embedding(db_session, org_id, "event", 1, "Windows Event ID 4625 failed login")
    store_embedding(db_session, org_id, "incident", 1, "Suspected ransomware incident on FINANCE-PC-21")
    db_session.commit()

    results = search(db_session, org_id, "ransomware", content_type="incident", k=5)

    assert len(results) == 1
    assert results[0]["content_type"] == "incident"


def test_store_embedding_ignores_empty_text(db_session, org_id):
    store_embedding(db_session, org_id, "event", 1, "")
    store_embedding(db_session, org_id, "event", 2, "   ")
    db_session.commit()

    results = search(db_session, org_id, "anything", k=5)
    assert results == []


def test_search_does_not_cross_organizations(db_session, org_id):
    from app.db_models import Organization

    other_org = Organization(name="Other Org", slug="other-org")
    db_session.add(other_org)
    db_session.commit()
    db_session.refresh(other_org)

    store_embedding(db_session, org_id, "event", 1, "Failed login attempt for user admin")
    store_embedding(db_session, other_org.id, "event", 2, "Failed login attempt for user admin")
    db_session.commit()

    results = search(db_session, org_id, "failed login", k=10)
    assert len(results) == 1


def test_ingestion_stores_event_embeddings(db_session, org_id):
    from app.ingestion import ingest

    ingest(db_session, org_id, "generic", [{
        "timestamp": "2026-07-24T09:00:00",
        "host": "FINANCE-PC-21",
        "user": "j.mehta",
        "event_type": "login_failed",
        "severity": "medium",
        "detail": "Failed login attempt",
    }])

    results = search(db_session, org_id, "failed login on finance PC", content_type="event", k=5)
    assert len(results) == 1
    assert "FINANCE-PC-21" in results[0]["text"]


def test_correlation_stores_incident_embedding(db_session, org_id):
    import json
    from pathlib import Path

    from app.correlation import run_correlation
    from app.ingestion import ingest

    samples = Path(__file__).resolve().parent.parent / "data" / "samples"
    ingest(db_session, org_id, "windows", json.loads((samples / "windows_events.json").read_text()))
    ingest(db_session, org_id, "firewall", json.loads((samples / "firewall.json").read_text()))
    ingest(db_session, org_id, "syslog", (samples / "syslog.log").read_text().splitlines())

    incidents = run_correlation(db_session, org_id)
    assert len(incidents) == 1

    results = search(db_session, org_id, "ransomware attack finance", content_type="incident", k=5)
    assert len(results) == 1
    assert results[0]["content_id"] == incidents[0].id
