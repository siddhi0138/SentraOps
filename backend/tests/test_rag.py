from app.rag import search, store_embedding


def test_store_and_search_finds_semantically_similar_text(db_session):
    store_embedding(db_session, "event", 1, "Failed login attempt for user admin from a suspicious IP address")
    store_embedding(db_session, "event", 2, "Quarterly sales report generated for the finance department")
    db_session.commit()

    results = search(db_session, "brute force attack on admin account", k=5)

    assert len(results) == 2
    # the login-failure text should rank above the unrelated sales report
    assert "Failed login" in results[0]["text"]


def test_search_respects_content_type_filter(db_session):
    store_embedding(db_session, "event", 1, "Windows Event ID 4625 failed login")
    store_embedding(db_session, "incident", 1, "Suspected ransomware incident on FINANCE-PC-21")
    db_session.commit()

    results = search(db_session, "ransomware", content_type="incident", k=5)

    assert len(results) == 1
    assert results[0]["content_type"] == "incident"


def test_store_embedding_ignores_empty_text(db_session):
    store_embedding(db_session, "event", 1, "")
    store_embedding(db_session, "event", 2, "   ")
    db_session.commit()

    results = search(db_session, "anything", k=5)
    assert results == []


def test_ingestion_stores_event_embeddings(db_session):
    from app.ingestion import ingest

    ingest(db_session, "generic", [{
        "timestamp": "2026-07-24T09:00:00",
        "host": "FINANCE-PC-21",
        "user": "j.mehta",
        "event_type": "login_failed",
        "severity": "medium",
        "detail": "Failed login attempt",
    }])

    results = search(db_session, "failed login on finance PC", content_type="event", k=5)
    assert len(results) == 1
    assert "FINANCE-PC-21" in results[0]["text"]


def test_correlation_stores_incident_embedding(db_session):
    import json
    from pathlib import Path

    from app.correlation import run_correlation
    from app.ingestion import ingest

    samples = Path(__file__).resolve().parent.parent / "data" / "samples"
    ingest(db_session, "windows", json.loads((samples / "windows_events.json").read_text()))
    ingest(db_session, "firewall", json.loads((samples / "firewall.json").read_text()))
    ingest(db_session, "syslog", (samples / "syslog.log").read_text().splitlines())

    incidents = run_correlation(db_session)
    assert len(incidents) == 1

    results = search(db_session, "ransomware attack finance", content_type="incident", k=5)
    assert len(results) == 1
    assert results[0]["content_id"] == incidents[0].id
