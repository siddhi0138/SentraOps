import json
from pathlib import Path

from app.command_center import get_queue
from app.correlation import run_correlation
from app.ingestion import ingest

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"


def _ransomware_incident(db_session, org_id):
    ingest(db_session, org_id, "windows", json.loads((SAMPLES / "windows_events.json").read_text()))
    ingest(db_session, org_id, "firewall", json.loads((SAMPLES / "firewall.json").read_text()))
    ingest(db_session, org_id, "syslog", (SAMPLES / "syslog.log").read_text().splitlines())
    return run_correlation(db_session, org_id)[0]


def test_get_queue_with_no_activity(db_session, org_id):
    queue = get_queue(db_session, org_id)
    assert queue["open_incidents"] == []
    assert queue["unassigned_open_incidents"] == 0
    assert queue["pending_actions"] == []


def test_get_queue_lists_open_incidents_prioritized_by_risk(db_session, org_id):
    incident = _ransomware_incident(db_session, org_id)
    queue = get_queue(db_session, org_id)
    assert len(queue["open_incidents"]) == 1
    assert queue["open_incidents"][0]["id"] == incident.id
    assert queue["unassigned_open_incidents"] == 1  # nobody has claimed it


def test_get_queue_excludes_closed_incidents(db_session, org_id):
    incident = _ransomware_incident(db_session, org_id)
    incident.status = "closed"
    db_session.commit()

    queue = get_queue(db_session, org_id)
    assert queue["open_incidents"] == []


def test_get_queue_scoped_to_organization(db_session, org_id):
    from app.db_models import Organization

    other_org = Organization(name="Other", slug="other-cc-org")
    db_session.add(other_org)
    db_session.commit()
    db_session.refresh(other_org)

    _ransomware_incident(db_session, org_id)

    own_queue = get_queue(db_session, org_id)
    other_queue = get_queue(db_session, other_org.id)
    assert len(own_queue["open_incidents"]) == 1
    assert other_queue["open_incidents"] == []


def test_command_center_queue_endpoint(client, viewer_headers):
    response = client.get("/command-center/queue", headers=viewer_headers)
    assert response.status_code == 200
    body = response.json()
    assert "open_incidents" in body
    assert "pending_actions" in body


def test_command_center_queue_includes_pending_actions_with_incident_title(client, analyst_headers):
    from tests.test_proposed_actions import _create_incident_with_proposed_actions

    incident_id, _action_ids = _create_incident_with_proposed_actions(client, analyst_headers)

    response = client.get("/command-center/queue", headers=analyst_headers)
    body = response.json()
    assert len(body["pending_actions"]) > 0
    assert body["pending_actions"][0]["incident_title"]
    assert body["pending_actions"][0]["incident_id"] == incident_id


def test_command_center_requires_authentication(client):
    assert client.get("/command-center/queue").status_code == 401


def test_create_and_list_shift_notes(client, analyst_headers, viewer_headers):
    response = client.post("/shift-notes", json={"body": "Quiet shift, nothing to flag."}, headers=analyst_headers)
    assert response.status_code == 200
    assert response.json()["author_email"]

    listing = client.get("/shift-notes", headers=viewer_headers)
    assert listing.status_code == 200
    assert len(listing.json()["notes"]) == 1


def test_shift_note_rejects_empty_body(client, analyst_headers):
    response = client.post("/shift-notes", json={"body": "   "}, headers=analyst_headers)
    assert response.status_code == 422


def test_viewer_cannot_create_shift_note(client, viewer_headers):
    response = client.post("/shift-notes", json={"body": "x"}, headers=viewer_headers)
    assert response.status_code == 403


def test_shift_notes_scoped_to_organization(client, admin_headers, other_org_admin_headers):
    client.post("/shift-notes", json={"body": "our note"}, headers=admin_headers)

    own = client.get("/shift-notes", headers=admin_headers).json()["notes"]
    other = client.get("/shift-notes", headers=other_org_admin_headers).json()["notes"]
    assert len(own) == 1
    assert other == []


def test_shift_notes_require_authentication(client):
    assert client.get("/shift-notes").status_code == 401
    assert client.post("/shift-notes", json={"body": "x"}).status_code == 401
