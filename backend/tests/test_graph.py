from app import graph


class FakeNode:
    def __init__(self, label, props):
        self.labels = [label]
        self._props = props

    def keys(self):
        return self._props.keys()

    def __getitem__(self, key):
        return self._props[key]


class FakeRelationship:
    def __init__(self, rel_type, props=None):
        self.type = rel_type
        self._props = props or {}

    def keys(self):
        return self._props.keys()

    def __getitem__(self, key):
        return self._props[key]


class FakeSession:
    def __init__(self, run_result=None):
        self.write_calls = []
        self.run_calls = []
        self._run_result = run_result or []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute_write(self, fn, *args):
        self.write_calls.append((fn, args))

    def run(self, query, **params):
        self.run_calls.append((query, params))
        return self._run_result


class FakeDriver:
    def __init__(self, run_result=None):
        self.fake_session = FakeSession(run_result)

    def session(self):
        return self.fake_session


def test_node_key_uses_correct_unique_property_per_label():
    assert graph._node_key(FakeNode("Host", {"name": "db-server-03"})) == "Host:db-server-03"
    assert graph._node_key(FakeNode("User", {"name": "svc_update"})) == "User:svc_update"
    assert graph._node_key(FakeNode("IP", {"address": "185.220.101.45"})) == "IP:185.220.101.45"
    assert graph._node_key(FakeNode("Incident", {"id": 7})) == "Incident:7"


def test_process_graph_result_dedupes_nodes_and_builds_edges():
    host = FakeNode("Host", {"name": "finance-pc-21"})
    user = FakeNode("User", {"name": "j.mehta"})
    incident = FakeNode("Incident", {"id": 1, "title": "Ransomware", "risk_level": "critical", "status": "open"})

    records = [
        {"a": user, "r": FakeRelationship("ACCESSED", {"count": 3}), "b": host},
        {"a": host, "r": FakeRelationship("PART_OF"), "b": incident},
        {"a": user, "r": FakeRelationship("PART_OF"), "b": incident},
    ]

    result = graph._process_graph_result(records)

    assert len(result["nodes"]) == 3
    keys = {n["key"] for n in result["nodes"]}
    assert keys == {"Host:finance-pc-21", "User:j.mehta", "Incident:1"}

    host_node = next(n for n in result["nodes"] if n["key"] == "Host:finance-pc-21")
    assert host_node["label"] == "Host"
    assert host_node["name"] == "finance-pc-21"

    incident_node = next(n for n in result["nodes"] if n["key"] == "Incident:1")
    assert incident_node["title"] == "Ransomware"
    assert incident_node["risk_level"] == "critical"

    assert len(result["edges"]) == 3
    accessed = next(e for e in result["edges"] if e["type"] == "ACCESSED")
    assert accessed["from"] == "User:j.mehta"
    assert accessed["to"] == "Host:finance-pc-21"
    assert accessed["count"] == 3


def test_process_graph_result_empty_when_no_records():
    assert graph._process_graph_result([]) == {"nodes": [], "edges": []}


def _create_incident(client, analyst_headers) -> int:
    client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    client.post("/correlate", headers=analyst_headers)
    return client.get("/incidents", headers=analyst_headers).json()["incidents"][0]["id"]


def test_resync_graph_builds_correct_rows_from_postgres(client, analyst_headers, db_session):
    incident_id = _create_incident(client, analyst_headers)
    me = client.get("/auth/me", headers=analyst_headers).json()
    org_id = me["organization_id"]

    fake_driver = FakeDriver()
    stats = graph.resync_graph(db_session, org_id, driver=fake_driver)

    assert stats["incidents"] == 1
    assert stats["events_processed"] > 0

    assert len(fake_driver.fake_session.write_calls) == 1
    fn, args = fake_driver.fake_session.write_calls[0]
    assert fn is graph._rebuild_graph_tx
    called_org_id, incident_rows, event_rows = args
    assert called_org_id == org_id
    assert incident_rows == [
        {
            "id": incident_id,
            "title": incident_rows[0]["title"],
            "risk_level": incident_rows[0]["risk_level"],
            "status": incident_rows[0]["status"],
        }
    ]
    # hosts/usernames are lowercased (case-insensitive identity, matching
    # the correlation engine's own convention); ip is passed through as-is.
    # org_key fields bake in organization_id so two tenants' same-named
    # hosts never collide in Neo4j (see graph._org_key).
    assert all(row["host"] == row["host"].lower() for row in event_rows)
    assert all(row["host_org_key"] == f"{org_id}:{row['host']}" for row in event_rows)
    assert all(row["user"] is None or row["user"] == row["user"].lower() for row in event_rows)
    assert all(row["incident_id"] == incident_id for row in event_rows)
    assert any(row["ip"] == "185.220.101.45" for row in event_rows)


def test_get_incident_subgraph_passes_incident_id_and_processes_result():
    host = FakeNode("Host", {"name": "finance-pc-21"})
    incident = FakeNode("Incident", {"id": 5, "title": "t", "risk_level": "high", "status": "open"})
    fake_driver = FakeDriver(run_result=[{"a": host, "r": FakeRelationship("PART_OF"), "b": incident}])

    result = graph.get_incident_subgraph(5, 42, driver=fake_driver)

    assert len(fake_driver.fake_session.run_calls) == 1
    query, params = fake_driver.fake_session.run_calls[0]
    assert params == {"id": 5, "org_id": 42}
    assert len(result["nodes"]) == 2
    assert len(result["edges"]) == 1


def test_get_entity_blast_radius_lowercases_host_and_clamps_hops():
    fake_driver = FakeDriver(run_result=[])
    graph.get_entity_blast_radius("host", "FINANCE-PC-21", 42, hops=10, driver=fake_driver)

    query, params = fake_driver.fake_session.run_calls[0]
    assert params == {"org_key": "42:finance-pc-21", "org_id": 42}
    assert "Host" in query
    assert "*1..4" in query  # hops clamped to the max of 4


def test_get_entity_blast_radius_does_not_lowercase_ip():
    fake_driver = FakeDriver(run_result=[])
    graph.get_entity_blast_radius("ip", "185.220.101.45", 42, driver=fake_driver)

    query, params = fake_driver.fake_session.run_calls[0]
    assert params == {"org_key": "42:185.220.101.45", "org_id": 42}
    assert "IP" in query


def test_get_entity_blast_radius_rejects_unknown_type():
    import pytest

    with pytest.raises(ValueError):
        graph.get_entity_blast_radius("process", "x", 42, driver=FakeDriver())


def test_get_full_graph_passes_org_id_and_limit():
    fake_driver = FakeDriver(run_result=[])
    graph.get_full_graph(42, limit=50, driver=fake_driver)

    query, params = fake_driver.fake_session.run_calls[0]
    assert params == {"org_id": 42, "limit": 50}
