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


def reset_client() -> None:
    global _client
    _client = None
