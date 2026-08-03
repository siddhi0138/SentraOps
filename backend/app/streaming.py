import json

import redis

from app.ingestion import ingest
from app.redis_client import get_client

# One shared consumer group per org stream, one consumer name - this
# project runs a single Celery worker (see docker-compose.yml's
# `celery_worker`, `--pool=solo`), so there's no need for multiple named
# consumers competing for messages within the group.
CONSUMER_GROUP = "ingest_consumers"
CONSUMER_NAME = "worker"


def stream_key(organization_id: int) -> str:
    return f"ingest_stream:{organization_id}"


def publish_raw_log(organization_id: int, source_type: str, raw_item, client: redis.Redis | None = None) -> str:
    """Queues one raw log item for asynchronous ingestion instead of
    parsing/persisting it inline in the request - the producer half of
    this project's Kafka+Spark-Streaming-equivalent pipeline (Redis
    Streams instead of a real Kafka broker/Spark cluster, consistent with
    this project's standing no-budget-infra substitution pattern - Celery
    +Redis already stands in for a task queue, pgvector for a dedicated
    vector DB). See consume_available() for the consumer half."""
    client = client or get_client()
    entry_id = client.xadd(stream_key(organization_id), {"source_type": source_type, "payload": json.dumps(raw_item)})
    return entry_id.decode() if isinstance(entry_id, bytes) else entry_id


def _ensure_group(client: redis.Redis, key: str) -> None:
    try:
        client.xgroup_create(key, CONSUMER_GROUP, id="0", mkstream=True)
    except redis.ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            raise


def consume_available(db, organization_id: int, max_messages: int = 500, client: redis.Redis | None = None) -> dict:
    """Drains whatever's currently waiting on this org's stream and runs
    each item through the real ingestion pipeline (app/ingestion.py.ingest()
    - the same one file uploads and connector syncs use). Dispatched as a
    Celery task right after publish (see app/tasks.py), so from the
    producer's perspective this behaves like real streaming: publish now,
    a separate worker process consumes moments later - without needing a
    dedicated always-running consumer daemon.

    Known limitation, stated rather than hidden: an item that fails to
    parse/ingest is left un-ACKed (visible via stream_status()'s `pending`
    count) rather than retried or moved to a dead-letter stream - acceptable
    for this project's scale, not something a production Kafka+Spark
    pipeline would leave unhandled."""
    client = client or get_client()
    key = stream_key(organization_id)
    _ensure_group(client, key)

    entries = client.xreadgroup(CONSUMER_GROUP, CONSUMER_NAME, {key: ">"}, count=max_messages)
    ingested = skipped = failed = 0

    for _key, messages in entries:
        for entry_id, fields in messages:
            source_type = fields[b"source_type"].decode()
            raw_item = json.loads(fields[b"payload"])
            try:
                events, batch_skipped = ingest(db, organization_id, source_type, [raw_item])
                ingested += len(events)
                skipped += batch_skipped
                client.xack(key, CONSUMER_GROUP, entry_id)
            except Exception:
                # Roll back so a broken item (e.g. an unknown source_type
                # raising before ingest()'s own commit) can't leave the
                # session in a state that poisons every message after it
                # in this same batch.
                db.rollback()
                failed += 1

    return {"ingested": ingested, "skipped": skipped, "failed": failed}


def stream_status(organization_id: int, client: redis.Redis | None = None) -> dict:
    client = client or get_client()
    key = stream_key(organization_id)
    queued = client.xlen(key)
    try:
        pending = client.xpending(key, CONSUMER_GROUP)
        pending_count = pending["pending"] if pending else 0
    except redis.ResponseError:
        # No consumer group yet (nothing has ever been published to this
        # org's stream) - zero pending, not an error.
        pending_count = 0
    return {"queued": queued, "pending": pending_count}
