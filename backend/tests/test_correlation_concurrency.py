import threading

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.correlation import run_correlation
from app.db import run_migrations
from app.db_models import Event, Incident
from app.ingestion import ingest


def test_concurrent_correlate_calls_do_not_double_claim_events(tmp_path):
    """Two /correlate calls firing at (as close to) the same instant must not
    both grab the same events. Uses two separate engines/sessions against the
    same on-disk sqlite file, synchronized with a barrier, to force genuine
    overlap rather than accidentally-sequential execution."""
    db_path = tmp_path / "concurrency.db"
    run_migrations(f"sqlite:///{db_path}")

    seed_engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    seed_session = sessionmaker(bind=seed_engine)()
    ingest(seed_session, "generic", [
        {"timestamp": "2026-07-24T09:00:00", "host": "HOST-A", "username": "alice", "event_type": "privilege_escalation", "severity": "high", "message": "a1"},
        {"timestamp": "2026-07-24T09:05:00", "host": "HOST-B", "username": "bob", "event_type": "privilege_escalation", "severity": "high", "message": "b1"},
    ])
    seed_session.close()
    seed_engine.dispose()

    barrier = threading.Barrier(2)
    results: list[list] = [None, None]  # type: ignore[list-item]
    errors: list[Exception] = []

    def worker(slot: int) -> None:
        engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False, "timeout": 10})
        session = sessionmaker(bind=engine)()
        try:
            barrier.wait(timeout=5)  # both threads call run_correlation as close together as possible
            results[slot] = run_correlation(session)
        except Exception as exc:  # pragma: no cover - surfaced via `errors` below
            errors.append(exc)
        finally:
            session.close()
            engine.dispose()

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)

    assert not errors, f"run_correlation raised under concurrency: {errors}"

    verify_engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    verify_session = sessionmaker(bind=verify_engine)()

    total_incidents_created = sum(len(r) for r in results)
    assert total_incidents_created == 2  # not 4 - neither thread re-processed the other's events

    all_incidents = verify_session.query(Incident).all()
    assert len(all_incidents) == 2

    # every event ended up attached to exactly one incident, none lost or doubled
    events = verify_session.query(Event).all()
    assert all(e.incident_id is not None for e in events)
    assert len({e.incident_id for e in events}) == 2
