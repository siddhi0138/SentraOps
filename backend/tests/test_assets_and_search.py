from app.db_models import Asset
from app.ingestion import ingest


def test_ingestion_creates_and_updates_asset(db_session):
    ingest(db_session, "generic", [
        {"timestamp": "2026-07-24T09:00:00", "host": "HOST-A", "event_type": "login_success", "severity": "low", "message": "m1"},
        {"timestamp": "2026-07-24T10:00:00", "host": "host-a", "event_type": "login_success", "severity": "low", "message": "m2"},
    ])

    assets = db_session.query(Asset).all()
    assert len(assets) == 1  # case-insensitive dedup
    assert assets[0].event_count == 2
    assert assets[0].last_seen.isoformat().startswith("2026-07-24T10:00:00")


def test_assets_api_list_and_update(client, analyst_headers):
    client.post("/simulate/phishing_ransomware", headers=analyst_headers)

    listing = client.get("/assets", headers=analyst_headers)
    assert listing.status_code == 200
    assert listing.json()["total"] >= 1

    asset_id = listing.json()["assets"][0]["id"]
    response = client.patch(
        f"/assets/{asset_id}",
        json={"department": "Finance", "criticality": "critical"},
        headers=analyst_headers,
    )
    assert response.status_code == 200
    assert response.json()["department"] == "Finance"
    assert response.json()["criticality"] == "critical"


def test_viewer_can_list_but_not_update_assets(client, analyst_headers, viewer_headers):
    client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    asset_id = client.get("/assets", headers=viewer_headers).json()["assets"][0]["id"]

    assert client.get("/assets", headers=viewer_headers).status_code == 200
    assert client.patch(f"/assets/{asset_id}", json={"department": "X"}, headers=viewer_headers).status_code == 403


def test_global_search_finds_events_incidents_and_assets(client, analyst_headers):
    client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    client.post("/correlate", headers=analyst_headers)

    result = client.get("/search", params={"q": "FINANCE-PC-21"}, headers=analyst_headers)
    assert result.status_code == 200
    body = result.json()
    assert len(body["events"]) > 0
    assert len(body["assets"]) > 0
