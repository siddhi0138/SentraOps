import os

import redis

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

_client: redis.Redis | None = None


def get_client() -> redis.Redis:
    """Lazily-created singleton shared by app/progress.py (pub/sub) and
    app/streaming.py (streams) - both are real uses of the same Redis
    instance already in docker-compose for Celery's broker/backend."""
    global _client
    if _client is None:
        _client = redis.Redis.from_url(REDIS_URL)
    return _client


def is_available() -> bool:
    """Quick reachability check with short timeouts. Celery's own dispatch
    retries for ~20s against an unreachable broker before giving up, so callers
    that want to fall back (see /investigate-live) check this first instead."""
    try:
        redis.Redis.from_url(REDIS_URL, socket_connect_timeout=2, socket_timeout=2).ping()
        return True
    except redis.RedisError:
        return False


def reset_client() -> None:
    global _client
    _client = None
