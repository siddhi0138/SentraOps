import os

from celery import Celery
from celery.schedules import crontab

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

# `include` is required, not optional: a worker process is started as
# `celery -A app.celery_app worker`, which only imports this module - it
# never imports app.tasks on its own, so without this the worker starts
# with an empty task registry and fails every dispatch with "Received
# unregistered task" (confirmed by actually starting a worker and checking
# its `[tasks]` list before adding this).
celery_app = Celery("sentraops", broker=REDIS_URL, backend=REDIS_URL, include=["app.tasks"])
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    task_track_started=True,
    # Tests set this so `.delay()` runs the task inline in the same process
    # instead of needing a real broker/worker - see conftest.py.
    task_always_eager=os.environ.get("CELERY_TASK_ALWAYS_EAGER", "false").lower() == "true",
    task_eager_propagates=True,
    # Beat runs embedded in the worker process (`celery worker -B`, see the
    # Helm chart's celery-worker.yaml) rather than as its own deployment -
    # fine at this project's single-worker scale; a real multi-worker
    # deployment would need a dedicated Beat process with leader election
    # instead, since two embedded Beats would each fire the schedule.
    beat_schedule={
        "daily-slack-summaries": {
            "task": "daily_slack_summaries_task",
            "schedule": crontab(hour=9, minute=0),
        },
    },
)
