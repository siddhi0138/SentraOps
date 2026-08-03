from app.db_models import Event, RawLog
from app.ingestion import ingest


def test_ingest_persists_raw_log_and_normalized_event(db_session, org_id):
    events, skipped = ingest(db_session, org_id, "generic", [{
        "timestamp": "2026-07-24T09:14:02",
        "host": "FINANCE-PC-21",
        "user": "j.mehta",
        "event_type": "email_opened",
        "detail": "Invoice_2026_0472.docx.exe opened from phishing email",
    }])

    assert skipped == 0
    assert len(events) == 1
    assert db_session.query(RawLog).count() == 1
    assert db_session.query(Event).count() == 1

    event = db_session.query(Event).one()
    assert event.username == "j.mehta"
    assert event.source_type == "generic"


def test_ingest_skips_unparseable_items_without_failing_batch(db_session, org_id):
    lines = [
        "Jul 24 09:16:40 db-server-03 sshd[1122]: Failed password for invalid user admin from 185.220.101.45 port 51824 ssh2",
        "this line is garbage and cannot be parsed",
    ]
    events, skipped = ingest(db_session, org_id, "syslog", lines)

    assert len(events) == 1
    assert skipped == 1
    # the raw payload is still kept for both, including the skipped one, for audit/replay
    assert db_session.query(RawLog).count() == 2
