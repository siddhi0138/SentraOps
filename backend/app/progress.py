import json

import redis

from app.redis_client import REDIS_URL, get_client  # noqa: F401  REDIS_URL re-exported, app.main imports it from here


def channel_name(run_id: int) -> str:
    return f"agent_run:{run_id}"


def publish_progress(run_id: int, event: dict) -> None:
    """Fire-and-forget publish to the run's progress channel. If Redis is
    unreachable this must not take the investigation down with it - the
    run still completes and persists normally, the frontend just falls
    back to polling GET /agent-runs/{run_id} instead of getting a live
    push (the WebSocket path already re-fetches that endpoint if the
    socket ever closes without a terminal event, so this is a soft
    dependency, not a hard one)."""
    try:
        get_client().publish(channel_name(run_id), json.dumps(event))
    except redis.RedisError:
        pass
