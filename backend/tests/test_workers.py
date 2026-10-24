from unittest.mock import patch

import pytest

import app.workers as workers
from app.celery_app import celery_app


@pytest.fixture(autouse=True)
def _fresh_cache_and_non_eager():
    was_eager = celery_app.conf.task_always_eager
    celery_app.conf.task_always_eager = False
    workers.reset_cache()
    yield
    celery_app.conf.task_always_eager = was_eager
    workers.reset_cache()


def test_true_in_eager_mode_without_touching_redis():
    celery_app.conf.task_always_eager = True
    with patch.object(workers, "redis_is_available", side_effect=AssertionError("should not be called")):
        assert workers.worker_available() is True


def test_false_when_redis_is_down():
    with patch.object(workers, "redis_is_available", return_value=False):
        assert workers.worker_available() is False


def test_false_when_redis_is_up_but_no_worker_answers():
    # The sleeping-free-tier-worker case: jobs would queue and never run.
    with patch.object(workers, "redis_is_available", return_value=True), \
         patch.object(celery_app.control, "ping", return_value=[]):
        assert workers.worker_available() is False


def test_true_when_a_worker_answers():
    with patch.object(workers, "redis_is_available", return_value=True), \
         patch.object(celery_app.control, "ping", return_value=[{"celery@host": {"ok": "pong"}}]):
        assert workers.worker_available() is True


def test_false_when_the_ping_itself_fails():
    with patch.object(workers, "redis_is_available", return_value=True), \
         patch.object(celery_app.control, "ping", side_effect=OSError("broker gone")):
        assert workers.worker_available() is False


def test_result_is_cached_briefly():
    with patch.object(workers, "redis_is_available", return_value=True), \
         patch.object(celery_app.control, "ping", return_value=[{"w": {"ok": "pong"}}]) as ping:
        assert workers.worker_available() is True
        assert workers.worker_available() is True
    assert ping.call_count == 1
