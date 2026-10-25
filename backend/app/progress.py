import json
import threading

import redis

from app.redis_client import REDIS_URL, get_client  # noqa: F401  REDIS_URL re-exported, app.main imports it from here


def channel_name(run_id: int) -> str:
    return f"agent_run:{run_id}"


# In-process copy of every run's progress events. When Redis is unreachable the
# investigation runs in a background thread of this same process (see
# tasks.run_investigation_in_background), and the WebSocket reads progress from
# here instead of a Redis channel. Only the most recent runs are kept.
_local_lock = threading.Lock()
_local_events: dict[int, list[dict]] = {}
_LOCAL_RUNS_KEPT = 50


def _record_local(run_id: int, event: dict) -> None:
    with _local_lock:
        if event.get("type") == "started":
            # A run's first event starts its history fresh, so events left over from an
            # earlier run that happened to have the same id (a reset database) never replay.
            _local_events.pop(run_id, None)
        _local_events.setdefault(run_id, []).append(event)
        while len(_local_events) > _LOCAL_RUNS_KEPT:
            del _local_events[next(iter(_local_events))]


def local_events_since(run_id: int, index: int) -> list[dict]:
    with _local_lock:
        return list(_local_events.get(run_id, [])[index:])


def publish_progress(run_id: int, event: dict) -> None:
    """Records the event in-process, then publishes it to the run's Redis channel.
    If Redis is unreachable this must not take the investigation down with it -
    the run still completes and persists normally, and the frontend gets its live
    progress from the in-process copy instead (the WebSocket path falls back to
    GET /agent-runs/{run_id} if the socket ever closes without a terminal event)."""
    _record_local(run_id, event)
    try:
        get_client().publish(channel_name(run_id), json.dumps(event))
    except redis.RedisError:
        pass
