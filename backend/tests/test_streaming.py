from unittest.mock import patch

import redis

from app.streaming import consume_available, publish_raw_log, stream_key, stream_status


class FakeRedisStreamClient:
    """A minimal in-memory double for the handful of Redis Streams
    commands app/streaming.py actually uses - proves this module's own
    consume/ack/pending-tracking logic is correct. It does NOT prove real
    Redis accepts the exact same call shapes (this project has hit that
    exact gap three times already: Celery task registration, Neo4j Cypher
    grammar, pgvector comparator wiring) - that's covered separately by
    live-verifying against a real `redis:7-alpine` container."""

    def __init__(self):
        self._streams: dict[str, list[tuple[bytes, dict]]] = {}
        self._groups: dict[tuple[str, str], dict] = {}
        self._next_id = 1

    def xadd(self, key: str, fields: dict) -> bytes:
        entry_id = f"{self._next_id}-0".encode()
        self._next_id += 1
        encoded = {k.encode(): v.encode() for k, v in fields.items()}
        self._streams.setdefault(key, []).append((entry_id, encoded))
        return entry_id

    def xgroup_create(self, key: str, group: str, id: str = "0", mkstream: bool = False):
        if (key, group) in self._groups:
            raise redis.ResponseError("BUSYGROUP Consumer Group name already exists")
        self._groups[(key, group)] = {"cursor": 0, "pending": {}}

    def xreadgroup(self, group: str, consumer: str, streams: dict, count: int = 10):
        result = []
        for key, _marker in streams.items():
            state = self._groups[(key, group)]
            entries = self._streams.get(key, [])[state["cursor"] : state["cursor"] + count]
            if not entries:
                continue
            state["cursor"] += len(entries)
            for entry_id, fields in entries:
                state["pending"][entry_id] = fields
            result.append((key.encode(), entries))
        return result

    def xack(self, key: str, group: str, entry_id) -> int:
        state = self._groups[(key, group)]
        return 1 if state["pending"].pop(entry_id, None) is not None else 0

    def xlen(self, key: str) -> int:
        return len(self._streams.get(key, []))

    def xpending(self, key: str, group: str) -> dict:
        state = self._groups.get((key, group))
        if state is None:
            raise redis.ResponseError("NOGROUP No such consumer group")
        return {"pending": len(state["pending"])}


def test_publish_and_consume_ingests_real_events(db_session, org_id):
    fake = FakeRedisStreamClient()
    raw_item = {
        "timestamp": "2026-07-27T00:00:00",
        "host": "stream-host-01",
        "event_type": "login_failed",
        "severity": "medium",
        "message": "failed login",
    }
    publish_raw_log(org_id, "generic", raw_item, client=fake)

    result = consume_available(db_session, org_id, client=fake)

    assert result == {"ingested": 1, "skipped": 0, "failed": 0}
    status = stream_status(org_id, client=fake)
    assert status == {"queued": 1, "pending": 0}  # acked on success, so nothing left pending


def test_consume_leaves_failed_item_unacked(db_session, org_id):
    fake = FakeRedisStreamClient()
    publish_raw_log(org_id, "not-a-real-source-type", {"host": "x"}, client=fake)

    result = consume_available(db_session, org_id, client=fake)

    assert result == {"ingested": 0, "skipped": 0, "failed": 1}
    assert stream_status(org_id, client=fake) == {"queued": 1, "pending": 1}


def test_consume_processes_multiple_messages_in_order(db_session, org_id):
    fake = FakeRedisStreamClient()
    for i in range(3):
        publish_raw_log(
            org_id,
            "generic",
            {"timestamp": "2026-07-27T00:00:00", "host": f"host-{i}", "event_type": "x", "message": "m"},
            client=fake,
        )

    result = consume_available(db_session, org_id, client=fake)
    assert result == {"ingested": 3, "skipped": 0, "failed": 0}

    # A second drain right after should find nothing new left to consume.
    assert consume_available(db_session, org_id, client=fake) == {"ingested": 0, "skipped": 0, "failed": 0}


def test_streams_are_isolated_per_organization(db_session, org_id):
    fake = FakeRedisStreamClient()
    other_org_id = org_id + 999
    publish_raw_log(org_id, "generic", {"host": "a"}, client=fake)

    assert stream_status(org_id, client=fake)["queued"] == 1
    assert stream_status(other_org_id, client=fake)["queued"] == 0
    assert stream_key(org_id) != stream_key(other_org_id)


def test_stream_status_with_no_group_yet_reports_zero_pending(org_id):
    fake = FakeRedisStreamClient()
    assert stream_status(org_id, client=fake) == {"queued": 0, "pending": 0}


def test_streaming_ingest_endpoint_queues_and_consumes(client, analyst_headers):
    fake = FakeRedisStreamClient()
    with patch("app.streaming.get_client", return_value=fake):
        response = client.post(
            "/ingest/generic/stream",
            json={"logs": [{"timestamp": "2026-07-27T00:00:00", "host": "h1", "event_type": "x", "message": "m"}]},
            headers=analyst_headers,
        )
        assert response.status_code == 200
        assert response.json() == {"queued": 1}

        # Celery eager mode ran consume_ingest_stream_task synchronously as
        # part of the request above, so the item should already be ingested.
        status_response = client.get("/streaming/status", headers=analyst_headers)
    assert status_response.json() == {"queued": 1, "pending": 0}


def test_streaming_endpoints_require_authentication(client):
    assert client.post("/ingest/generic/stream", json={"logs": []}).status_code == 401
    assert client.get("/streaming/status").status_code == 401


def test_viewer_can_read_status_but_not_ingest(client, analyst_headers, viewer_headers):
    fake = FakeRedisStreamClient()
    with patch("app.streaming.get_client", return_value=fake):
        assert (
            client.post("/ingest/generic/stream", json={"logs": [{"host": "h"}]}, headers=viewer_headers).status_code
            == 403
        )
        assert client.get("/streaming/status", headers=viewer_headers).status_code == 200


def test_streaming_ingest_scoped_to_organization(client, admin_headers, other_org_admin_headers):
    fake = FakeRedisStreamClient()
    with patch("app.streaming.get_client", return_value=fake):
        client.post(
            "/ingest/generic/stream",
            json={"logs": [{"timestamp": "2026-07-27T00:00:00", "host": "h1", "event_type": "x", "message": "m"}]},
            headers=admin_headers,
        )
        own_status = client.get("/streaming/status", headers=admin_headers).json()
        other_status = client.get("/streaming/status", headers=other_org_admin_headers).json()

    assert own_status["queued"] == 1
    assert other_status["queued"] == 0
