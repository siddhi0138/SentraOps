from datetime import datetime
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import Query, sessionmaker

from app.db import run_migrations
from app.db_models import Asset, Organization
from app.ingestion import _upsert_asset


def _make_session(db_path):
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    return sessionmaker(bind=engine)()


def _seed_org(db_path) -> int:
    session = _make_session(db_path)
    org = Organization(name="Test Org", slug="test-org")
    session.add(org)
    session.commit()
    org_id = org.id
    session.close()
    return org_id


def test_upsert_asset_recovers_when_a_concurrent_insert_wins_the_race(tmp_path):
    """Forces the exact race _upsert_asset has to survive: another
    transaction commits the same host (possibly different casing) in the
    gap between this call's own lookup and its insert attempt.

    A real thread-timing test can't reliably reproduce this - SQLite and the
    GIL tend to serialize the fast path before two threads ever actually
    overlap, and SQLite's isolation semantics don't reliably freeze a stale
    read across connections the way Postgres's would either (both tried and
    both let the race disappear). So this drives the exact interleaving by
    hand: patch the initial lookup to report "not found" once - exactly what
    a stale read racing a concurrent insert would see - while a genuinely
    conflicting row already exists in the database, then assert the
    SAVEPOINT+IntegrityError fallback recovers instead of crashing or
    creating a duplicate."""
    db_path = tmp_path / "asset_race.db"
    run_migrations(f"sqlite:///{db_path}")
    org_id = _seed_org(db_path)

    winner_session = _make_session(db_path)
    timestamp = datetime(2026, 7, 24, 9, 0, 0)

    # The "other" concurrent request already won and committed.
    _upsert_asset(winner_session, org_id, "FINANCE-PC-21", timestamp)
    winner_session.commit()
    winner_session.close()

    loser_session = _make_session(db_path)
    original_first = Query.first
    calls = {"n": 0}

    def stale_first(self):
        calls["n"] += 1
        if calls["n"] == 1:
            return None  # simulate the race: this lookup ran before the winner's commit was visible
        return original_first(self)

    with patch.object(Query, "first", stale_first):
        _upsert_asset(loser_session, org_id, "finance-pc-21", timestamp)  # must not raise
    loser_session.commit()
    loser_session.close()

    verify_session = _make_session(db_path)
    assets = verify_session.query(Asset).all()

    assert len(assets) == 1  # no duplicate row from the "losing" side
    assert assets[0].event_count == 2  # both sightings still recorded


def test_upsert_asset_normal_path_still_dedupes_across_sessions(tmp_path):
    """Sanity check without any mocking: sequential calls from different
    sessions for the same host (different casing) never create two rows."""
    db_path = tmp_path / "asset_sequential.db"
    run_migrations(f"sqlite:///{db_path}")
    org_id = _seed_org(db_path)
    timestamp = datetime(2026, 7, 24, 9, 0, 0)

    session_a = _make_session(db_path)
    _upsert_asset(session_a, org_id, "FINANCE-PC-21", timestamp)
    session_a.commit()
    session_a.close()

    session_b = _make_session(db_path)
    _upsert_asset(session_b, org_id, "finance-pc-21", timestamp)
    session_b.commit()
    session_b.close()

    verify_session = _make_session(db_path)
    assets = verify_session.query(Asset).all()
    assert len(assets) == 1
    assert assets[0].event_count == 2
