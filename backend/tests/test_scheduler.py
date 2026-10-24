from datetime import date, datetime, timezone

from app.scheduler import DAILY_HOUR_UTC, maybe_run_daily


def _at(hour, day=1):
    return datetime(2026, 10, day, hour, 5, tzinfo=timezone.utc)


def test_runs_once_at_the_daily_hour_when_redis_is_down():
    calls = []
    last = maybe_run_daily(_at(DAILY_HOUR_UTC), None, redis_ok=False, run=lambda: calls.append(1))
    assert calls == [1]
    assert last == date(2026, 10, 1)

    # Same day, still in the hour: not repeated.
    maybe_run_daily(_at(DAILY_HOUR_UTC), last, redis_ok=False, run=lambda: calls.append(1))
    assert calls == [1]

    # Next day: runs again.
    maybe_run_daily(_at(DAILY_HOUR_UTC, day=2), last, redis_ok=False, run=lambda: calls.append(1))
    assert calls == [1, 1]


def test_does_nothing_when_redis_is_up_because_celery_beat_sends_them():
    calls = []
    last = maybe_run_daily(_at(DAILY_HOUR_UTC), None, redis_ok=True, run=lambda: calls.append(1))
    assert calls == []
    assert last == date(2026, 10, 1)


def test_does_nothing_outside_the_daily_hour():
    calls = []
    assert maybe_run_daily(_at(DAILY_HOUR_UTC + 1), None, redis_ok=False, run=lambda: calls.append(1)) is None
    assert calls == []


def test_a_failing_run_does_not_raise():
    def boom():
        raise RuntimeError("slack down")

    assert maybe_run_daily(_at(DAILY_HOUR_UTC), None, redis_ok=False, run=boom) == date(2026, 10, 1)
