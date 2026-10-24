"""Backup for Celery Beat's daily Slack summaries (app/celery_app.py's beat_schedule).

Celery Beat needs Redis and a running worker. When Redis is unreachable, this
thread, started with the app, sends the same daily summaries itself at the same
hour. While Redis is reachable it does nothing, so summaries are never sent twice."""

import logging
import threading
from datetime import date, datetime, timezone
from typing import Callable

from app.redis_client import is_available as redis_is_available

logger = logging.getLogger(__name__)

DAILY_HOUR_UTC = 9  # matches crontab(hour=9, minute=0) in app/celery_app.py


def maybe_run_daily(
    now: datetime, last_run: date | None, redis_ok: bool, run: Callable[[], None]
) -> date | None:
    """Runs `run` once per day during DAILY_HOUR_UTC when Redis is down. Returns the
    date it last counted as handled, so the caller doesn't repeat it within that hour."""
    if now.hour != DAILY_HOUR_UTC or last_run == now.date():
        return last_run
    if not redis_ok:
        try:
            run()
        except Exception:
            logger.exception("Backup daily Slack summaries failed")
    return now.date()


def _send_daily_summaries() -> None:
    from app.db import SessionLocal
    from app.slack_bot import send_daily_summaries

    db = SessionLocal()
    try:
        send_daily_summaries(db)
    finally:
        db.close()


def start() -> threading.Event:
    """Starts the backup scheduler thread; set the returned event to stop it."""
    stop = threading.Event()

    def loop() -> None:
        last_run = None
        while not stop.wait(60):
            now = datetime.now(timezone.utc)
            if now.hour == DAILY_HOUR_UTC and last_run != now.date():
                last_run = maybe_run_daily(now, last_run, redis_is_available(), _send_daily_summaries)

    threading.Thread(target=loop, name="backup-scheduler", daemon=True).start()
    return stop
