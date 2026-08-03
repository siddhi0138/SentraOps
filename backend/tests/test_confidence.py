from datetime import datetime, timezone

from app.confidence import compute_dual_evidence_confidence
from app.db_models import Event
from tests.test_graph import FakeDriver


def _event(db_session, org_id, host: str) -> int:
    event = Event(
        organization_id=org_id,
        host=host,
        timestamp=datetime.now(timezone.utc),
        event_type="login_success",
        severity="low",
        message="m",
        source_type="test",
    )
    db_session.add(event)
    db_session.commit()
    return event.id


def test_both_signals_strong_yields_high_confidence(db_session, org_id):
    event_id = _event(db_session, org_id, "finance-pc-21")
    evidence = [{"content_type": "event", "content_id": event_id, "text": "t", "score": 0.9}]
    # one connected edge for the host -> structurally corroborated
    driver = FakeDriver(run_result=_singleton_result(degree=1))

    result = compute_dual_evidence_confidence(db_session, org_id, evidence, driver=driver)

    assert result["confidence"] == "high"
    assert result["semantic_score"] == 0.9
    assert result["structural_corroboration"] == 1.0


def test_semantic_strong_but_structurally_isolated_yields_medium():
    evidence = [{"content_type": "incident", "content_id": 1, "text": "t", "score": 0.9}]
    driver = FakeDriver(run_result=_singleton_result(degree=0))

    result = compute_dual_evidence_confidence(_NullDb(), 1, evidence, driver=driver)

    assert result["confidence"] == "medium"
    assert result["structural_corroboration"] == 0.0


def test_no_evidence_yields_low_confidence():
    driver = FakeDriver(run_result=[])
    result = compute_dual_evidence_confidence(_NullDb(), 1, [], driver=driver)
    assert result["confidence"] == "low"
    assert result["semantic_score"] == 0.0
    assert result["structural_corroboration"] == 0.0


def test_graph_unavailable_fails_open_instead_of_raising():
    evidence = [{"content_type": "incident", "content_id": 1, "text": "t", "score": 0.9}]

    class ExplodingDriver:
        def session(self):
            raise ConnectionError("neo4j is down")

    result = compute_dual_evidence_confidence(_NullDb(), 1, evidence, driver=ExplodingDriver())

    assert result["confidence"] == "medium"  # semantic alone still counts
    assert result["structural_corroboration"] == 0.0
    assert result["evidence_checked"] == 0


class _NullDb:
    """Evidence in these tests is either 'incident' (no DB lookup needed) or
    absent, so a real db_session isn't required - avoids coupling every test
    here to the Event-table setup that only the 'event' content_type path
    actually needs."""

    def query(self, *args, **kwargs):
        raise AssertionError("db.query should not be called for incident-only evidence")


def _singleton_result(*, degree: int):
    class _Record:
        def __getitem__(self, key):
            assert key == "degree"
            return degree

    class _Result:
        def single(self):
            return _Record()

    return _Result()
