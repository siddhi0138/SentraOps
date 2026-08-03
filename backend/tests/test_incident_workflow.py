def _create_one_incident(client, analyst_headers) -> int:
    client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    client.post("/correlate", headers=analyst_headers)
    return client.get("/incidents", headers=analyst_headers).json()["incidents"][0]["id"]


def test_correlation_notifies_admin_and_analyst(client, admin_headers, analyst_headers):
    _create_one_incident(client, analyst_headers)

    admin_notifications = client.get("/notifications", headers=admin_headers).json()
    assert admin_notifications["unread_count"] >= 1
    assert "New" in admin_notifications["notifications"][0]["message"]


def test_assigning_incident_notifies_assignee(client, admin_headers, analyst_headers):
    incident_id = _create_one_incident(client, analyst_headers)

    users = client.get("/users", headers=admin_headers).json()
    analyst_user_id = next(u["id"] for u in users if u["email"] == "analyst@example.com")

    response = client.patch(f"/incidents/{incident_id}", json={"assignee_id": analyst_user_id}, headers=admin_headers)
    assert response.status_code == 200
    assert response.json()["assignee_email"] == "analyst@example.com"

    notifications = client.get("/notifications", headers=analyst_headers).json()
    assert any("assigned" in n["message"] for n in notifications["notifications"])


def test_unassign_incident_with_explicit_null(client, admin_headers, analyst_headers):
    incident_id = _create_one_incident(client, analyst_headers)
    users = client.get("/users", headers=admin_headers).json()
    analyst_user_id = next(u["id"] for u in users if u["email"] == "analyst@example.com")

    client.patch(f"/incidents/{incident_id}", json={"assignee_id": analyst_user_id}, headers=admin_headers)
    response = client.patch(f"/incidents/{incident_id}", json={"assignee_id": None}, headers=admin_headers)
    assert response.json()["assignee_id"] is None


def test_update_priority(client, analyst_headers):
    incident_id = _create_one_incident(client, analyst_headers)
    response = client.patch(f"/incidents/{incident_id}", json={"priority": "low"}, headers=analyst_headers)
    assert response.json()["priority"] == "low"


def test_mark_notification_read(client, admin_headers, analyst_headers):
    _create_one_incident(client, analyst_headers)
    notification_id = client.get("/notifications", headers=admin_headers).json()["notifications"][0]["id"]

    response = client.patch(f"/notifications/{notification_id}/read", headers=admin_headers)
    assert response.status_code == 200
    assert response.json()["is_read"] is True

    assert client.get("/notifications", headers=admin_headers).json()["unread_count"] == 0


def test_cannot_read_another_users_notification(client, admin_headers, analyst_headers):
    _create_one_incident(client, analyst_headers)
    notification_id = client.get("/notifications", headers=admin_headers).json()["notifications"][0]["id"]

    response = client.patch(f"/notifications/{notification_id}/read", headers=analyst_headers)
    assert response.status_code == 404


def test_add_and_list_comment(client, analyst_headers):
    incident_id = _create_one_incident(client, analyst_headers)

    response = client.post(f"/incidents/{incident_id}/comments", json={"body": "Looks like real ransomware."}, headers=analyst_headers)
    assert response.status_code == 200
    assert response.json()["author_email"] == "analyst@example.com"

    detail = client.get(f"/incidents/{incident_id}", headers=analyst_headers).json()
    assert len(detail["comments"]) == 1
    assert detail["comments"][0]["body"] == "Looks like real ransomware."


def test_viewer_cannot_comment(client, analyst_headers, viewer_headers):
    incident_id = _create_one_incident(client, analyst_headers)
    response = client.post(f"/incidents/{incident_id}/comments", json={"body": "hi"}, headers=viewer_headers)
    assert response.status_code == 403


def test_events_csv_export(client, analyst_headers):
    client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    response = client.get("/events/export.csv", headers=analyst_headers)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "attachment" in response.headers["content-disposition"]
    assert response.text.startswith("id,timestamp,host")


def test_incident_report_download(client, analyst_headers):
    incident_id = _create_one_incident(client, analyst_headers)
    response = client.get(f"/incidents/{incident_id}/report.md", headers=analyst_headers)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/markdown")
    assert "Incident Report" in response.text


def test_incidents_csv_export(client, analyst_headers):
    _create_one_incident(client, analyst_headers)
    response = client.get("/incidents/export.csv", headers=analyst_headers)
    assert response.status_code == 200
    assert "attachment" in response.headers["content-disposition"]
    assert response.text.startswith("id,title")
