"""Whether a Celery worker is actually there to take a job.

Redis being reachable isn't enough. On Render's free plan the worker is a web
service that sleeps when idle, so jobs queued while it sleeps would just sit
there and an investigation would hang as "running". Callers hand work to Celery
only when this says a worker answers, and otherwise run it in this process."""

import time

from app.celery_app import celery_app
from app.redis_client import is_available as redis_is_available

_CACHE_SECONDS = 30
_PING_TIMEOUT_SECONDS = 1.5
_cached: tuple[float, bool] | None = None


def worker_available() -> bool:
    """True in eager mode (tests), or when Redis is reachable and at least one
    worker replies to a ping. The answer is cached for 30 seconds so a burst of
    requests doesn't ping the workers each time."""
    global _cached
    if celery_app.conf.task_always_eager:
        return True

    now = time.monotonic()
    if _cached is not None and now - _cached[0] < _CACHE_SECONDS:
        return _cached[1]

    available = False
    if redis_is_available():
        try:
            available = bool(celery_app.control.ping(timeout=_PING_TIMEOUT_SECONDS))
        except Exception:
            available = False
    _cached = (now, available)
    return available


def reset_cache() -> None:
    global _cached
    _cached = None
