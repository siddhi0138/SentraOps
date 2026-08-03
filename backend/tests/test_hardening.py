import io


def test_register_rejects_short_password(client, test_org):
    org_slug, _admin = test_org
    response = client.post(
        "/auth/register", json={"email": "weak@example.com", "password": "short", "organization_slug": org_slug}
    )
    assert response.status_code == 422


def test_register_rejects_empty_password(client, test_org):
    org_slug, _admin = test_org
    response = client.post(
        "/auth/register", json={"email": "empty@example.com", "password": "", "organization_slug": org_slug}
    )
    assert response.status_code == 422


def _create_one_incident(client, analyst_headers) -> int:
    client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    client.post("/correlate", headers=analyst_headers)
    return client.get("/incidents", headers=analyst_headers).json()["incidents"][0]["id"]


def test_incident_status_cannot_be_explicitly_nulled(client, analyst_headers):
    incident_id = _create_one_incident(client, analyst_headers)
    response = client.patch(f"/incidents/{incident_id}", json={"status": None}, headers=analyst_headers)
    assert response.status_code == 400


def test_incident_priority_cannot_be_explicitly_nulled(client, analyst_headers):
    incident_id = _create_one_incident(client, analyst_headers)
    response = client.patch(f"/incidents/{incident_id}", json={"priority": None}, headers=analyst_headers)
    assert response.status_code == 400


def test_incident_assignee_can_still_be_explicitly_nulled(client, analyst_headers):
    incident_id = _create_one_incident(client, analyst_headers)
    response = client.patch(f"/incidents/{incident_id}", json={"assignee_id": None}, headers=analyst_headers)
    assert response.status_code == 200


def test_asset_criticality_cannot_be_explicitly_nulled(client, analyst_headers):
    client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    asset_id = client.get("/assets", headers=analyst_headers).json()["assets"][0]["id"]

    response = client.patch(f"/assets/{asset_id}", json={"criticality": None}, headers=analyst_headers)
    assert response.status_code == 400


def test_asset_department_can_still_be_explicitly_nulled(client, analyst_headers):
    client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    asset_id = client.get("/assets", headers=analyst_headers).json()["assets"][0]["id"]

    client.patch(f"/assets/{asset_id}", json={"department": "Finance"}, headers=analyst_headers)
    response = client.patch(f"/assets/{asset_id}", json={"department": None}, headers=analyst_headers)
    assert response.status_code == 200
    assert response.json()["department"] is None


def test_events_csv_export_neutralizes_formula_injection(client, analyst_headers):
    client.post("/ingest/generic", json={"logs": [{
        "timestamp": "2026-07-24T09:00:00",
        "host": "HOST-A",
        "username": "attacker",
        "event_type": "login_failed",
        "severity": "medium",
        "message": "=cmd|'/c calc'!A1",
    }]}, headers=analyst_headers)

    response = client.get("/events/export.csv", headers=analyst_headers)
    assert response.status_code == 200
    assert "'=cmd|" in response.text  # prefixed with ' so Excel treats it as text, not a formula
    assert ",=cmd|" not in response.text  # i.e. never appears unprefixed at the start of a cell


def test_ingest_upload_json_file_reaches_upload_endpoint_not_ingest_by_source_type(client, analyst_headers):
    # Regression test: /ingest/{source_type} was registered before
    # /ingest/upload, so its path pattern matched "/ingest/upload" first
    # (source_type="upload") and this endpoint was completely unreachable.
    payload = b'[{"timestamp": "2026-07-24T09:00:00", "host": "HOST-A", "event_type": "login_success", "severity": "low", "message": "hi"}]'
    file = io.BytesIO(payload)
    response = client.post(
        "/ingest/upload",
        params={"source_type": "generic"},
        files={"file": ("events.json", file, "application/json")},
        headers=analyst_headers,
    )
    assert response.status_code == 200
    assert response.json() == {"ingested": 1, "skipped": 0}


def test_ingest_upload_csv_file(client, analyst_headers):
    csv_content = "timestamp,host,event_type,severity,message\n2026-07-24T09:00:00,HOST-A,login_success,low,hi from csv\n"
    file = io.BytesIO(csv_content.encode())
    response = client.post(
        "/ingest/upload",
        params={"source_type": "generic"},
        files={"file": ("events.csv", file, "text/csv")},
        headers=analyst_headers,
    )
    assert response.status_code == 200
    assert response.json() == {"ingested": 1, "skipped": 0}


def test_ingest_upload_rejects_invalid_json_with_400(client, analyst_headers):
    file = io.BytesIO(b"{not valid json")
    response = client.post(
        "/ingest/upload",
        params={"source_type": "generic"},
        files={"file": ("bad.json", file, "application/json")},
        headers=analyst_headers,
    )
    assert response.status_code == 400


def test_ingest_upload_rejects_non_utf8_with_400(client, analyst_headers):
    file = io.BytesIO(b"\xff\xfe\x00\x01invalid utf8")
    response = client.post(
        "/ingest/upload",
        params={"source_type": "generic"},
        files={"file": ("bad.json", file, "application/json")},
        headers=analyst_headers,
    )
    assert response.status_code == 400
