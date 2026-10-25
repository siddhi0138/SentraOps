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


def test_store_embeddings_skips_and_returns_false_when_service_is_down(db_session, org_id):
    from unittest.mock import patch

    from app.db_models import Embedding
    from app.rag import store_embeddings

    with patch("app.rag.embed_texts", side_effect=RuntimeError("429 Too Many Requests")):
        stored = store_embeddings(db_session, org_id, [("event", 1, "Failed login for admin")])
    db_session.commit()

    assert stored is False
    assert db_session.query(Embedding).count() == 0


def test_search_falls_back_to_keyword_matching_when_embedding_service_is_down(client, analyst_headers):
    from unittest.mock import patch

    client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    client.post("/correlate", headers=analyst_headers)

    with patch("app.rag.embed_text", side_effect=RuntimeError("429 Too Many Requests")):
        response = client.get("/rag/search", params={"q": "login"}, headers=analyst_headers)

    assert response.status_code == 200
    results = response.json()["results"]
    assert results
    assert all("login" in r["text"].lower() for r in results)
    assert {"content_type", "content_id", "text", "score"} <= set(results[0])


def test_keyword_fallback_returns_nothing_for_unmatched_or_empty_queries(client, analyst_headers):
    from unittest.mock import patch

    client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    with patch("app.rag.embed_text", side_effect=RuntimeError("down")):
        assert client.get("/rag/search", params={"q": "zzzqqqxxx"}, headers=analyst_headers).json()["results"] == []
        assert client.get("/rag/search", params={"q": "the and"}, headers=analyst_headers).json()["results"] == []


def test_simulate_succeeds_without_vectors_then_reindex_fills_them_in(client, analyst_headers, admin_headers, db_session):
    from unittest.mock import patch

    from app.db_models import Embedding

    with patch("app.rag.embed_texts", side_effect=RuntimeError("429 Too Many Requests")):
        response = client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    assert response.status_code == 200
    assert response.json()["mode"] == "synthetic"
    db_session.expire_all()
    assert db_session.query(Embedding).count() == 0

    reindex = client.post("/rag/reindex", headers=admin_headers)
    assert reindex.status_code == 200
    assert reindex.json()["embedded"] > 0
    db_session.expire_all()
    assert db_session.query(Embedding).count() == reindex.json()["embedded"]


def test_search_always_includes_exact_keyword_hits_next_to_vector_hits(db_session, org_id):
    from app.db_models import Embedding, Event
    from app.rag import search

    # Plenty of unrelated embedded text, so a vector search returns k unrelated rows...
    for i in range(8):
        store_embedding(db_session, org_id, "knowledge_chunk", 100 + i, f"Quarterly finance report number {i} for the sales department")
    # ...and one event that only a literal match on its host name would find (it has no vector).
    from datetime import datetime, timezone
    db_session.add(Event(organization_id=org_id, timestamp=datetime.now(timezone.utc), host="zeta-db-77", username="mallory",
                         event_type="login_failed", severity="high", message="Repeated failed login", source_type="generic"))
    db_session.commit()

    results = search(db_session, org_id, "what happened on zeta-db-77", k=6)
    assert any(r["content_type"] == "event" and "zeta-db-77" in r["text"] for r in results)
    assert len(results) <= 6


# --- background retry of missing search vectors -----------------------------------------

def _event(db_session, org_id, host="retry-host-1"):
    from datetime import datetime, timezone

    from app.db_models import Event

    event = Event(organization_id=org_id, timestamp=datetime.now(timezone.utc), host=host, username="u", event_type="login_failed",
                  severity="low", message="Failed login", source_type="generic")
    db_session.add(event)
    db_session.commit()
    return event


def test_backfill_loop_fills_in_vectors_and_stops_when_nothing_is_missing(db_session, org_id):
    from app.db_models import Embedding
    from app.reindex import _backfill_loop, has_missing

    _event(db_session, org_id)
    assert has_missing(db_session, org_id)

    sleeps = []
    _backfill_loop(org_id, (5, 10, 20), lambda: db_session, sleep=sleeps.append)

    # First attempt filled it in; the second delay found nothing missing and stopped.
    assert sleeps == [5, 10]
    assert db_session.query(Embedding).filter_by(content_type="event").count() == 1
    assert not has_missing(db_session, org_id)


def test_backfill_loop_keeps_trying_while_the_service_is_down_and_releases_the_org(db_session, org_id):
    from unittest.mock import patch

    from app.reindex import _backfill_loop, _in_flight

    _event(db_session, org_id)
    _in_flight.add(org_id)
    sleeps = []
    with patch("app.rag.embed_texts", side_effect=RuntimeError("429")):
        _backfill_loop(org_id, (1, 2, 3), lambda: db_session, sleep=sleeps.append)

    assert sleeps == [1, 2, 3]  # tried every delay
    assert org_id not in _in_flight  # a later call can start a new retry


def test_schedule_backfill_does_nothing_when_disabled_and_only_one_runs_per_org(monkeypatch):
    from unittest.mock import patch

    from app import reindex

    monkeypatch.setenv("EMBEDDING_BACKFILL_RETRY", "false")
    assert reindex.schedule_backfill(4242) is False

    monkeypatch.setenv("EMBEDDING_BACKFILL_RETRY", "true")
    with patch.object(reindex.threading, "Thread") as thread:
        assert reindex.schedule_backfill(4242) is True
        assert reindex.schedule_backfill(4242) is False  # already in flight
    assert thread.call_count == 1
    reindex._in_flight.discard(4242)


def test_failed_embedding_write_schedules_a_retry(db_session, org_id):
    from unittest.mock import patch

    from app.rag import store_embeddings

    with patch("app.rag.embed_texts", side_effect=RuntimeError("429")), patch("app.reindex.schedule_backfill") as schedule:
        assert store_embeddings(db_session, org_id, [("event", 1, "some text")]) is False
    schedule.assert_called_once_with(org_id)
