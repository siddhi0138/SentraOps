def test_get_current_organization(client, viewer_headers):
    response = client.get("/organizations/current", headers=viewer_headers)
    assert response.status_code == 200
    assert response.json()["name"] == "Test Org"


def test_rename_organization_requires_admin(client, analyst_headers, admin_headers):
    assert client.patch("/organizations/current", json={"name": "New Name"}, headers=analyst_headers).status_code == 403

    response = client.patch("/organizations/current", json={"name": "New Name"}, headers=admin_headers)
    assert response.status_code == 200
    assert response.json()["name"] == "New Name"


def test_rename_organization_creates_audit_entry(client, admin_headers):
    client.patch("/organizations/current", json={"name": "Renamed Co"}, headers=admin_headers)

    entries = client.get("/audit-log", headers=admin_headers).json()["entries"]
    entry = next(e for e in entries if e["action"] == "org_renamed")
    assert entry["details"]["new_name"] == "Renamed Co"
    assert entry["actor_email"]


def test_rotate_invite_code_changes_slug_and_logs(client, admin_headers):
    before = client.get("/organizations/current", headers=admin_headers).json()["slug"]
    response = client.post("/organizations/current/rotate-invite-code", headers=admin_headers)

    assert response.status_code == 200
    after = response.json()["slug"]
    assert after != before

    entries = client.get("/audit-log", headers=admin_headers).json()["entries"]
    entry = next(e for e in entries if e["action"] == "invite_code_rotated")
    assert entry["details"]["old_slug"] == before
    assert entry["details"]["new_slug"] == after


def test_rotate_invite_code_requires_admin(client, viewer_headers):
    assert client.post("/organizations/current/rotate-invite-code", headers=viewer_headers).status_code == 403


def test_create_api_key_requires_admin(client, analyst_headers, admin_headers):
    assert client.post("/api-keys", json={"name": "CI key"}, headers=analyst_headers).status_code == 403

    response = client.post("/api-keys", json={"name": "CI key"}, headers=admin_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["key"].startswith("csk_")
    assert body["key_prefix"] == body["key"][:12]
    assert body["acts_as_email"]


def test_api_key_never_exposed_again_after_creation(client, admin_headers):
    client.post("/api-keys", json={"name": "CI key"}, headers=admin_headers)
    listing = client.get("/api-keys", headers=admin_headers).json()["api_keys"]
    assert len(listing) == 1
    assert "key" not in listing[0]
    assert "key_hash" not in listing[0]


def test_api_key_authenticates_as_its_acting_user(client, admin_headers):
    created = client.post("/api-keys", json={"name": "CI key"}, headers=admin_headers).json()
    raw_key = created["key"]

    response = client.get("/auth/me", headers={"X-API-Key": raw_key})
    assert response.status_code == 200
    assert response.json()["role"] == "admin"  # acts as the creating admin by default


def test_api_key_acting_as_viewer_cannot_do_admin_actions(client, admin_headers, viewer_headers):
    viewer_id = client.get("/auth/me", headers=viewer_headers).json()["id"]
    created = client.post("/api-keys", json={"name": "Viewer key", "user_id": viewer_id}, headers=admin_headers).json()

    response = client.get("/auth/me", headers={"X-API-Key": created["key"]})
    assert response.json()["role"] == "viewer"

    assert client.post("/api-keys", json={"name": "x"}, headers={"X-API-Key": created["key"]}).status_code == 403


def test_revoked_api_key_cannot_authenticate(client, admin_headers):
    created = client.post("/api-keys", json={"name": "CI key"}, headers=admin_headers).json()
    raw_key = created["key"]
    key_id = created["id"]

    assert client.get("/auth/me", headers={"X-API-Key": raw_key}).status_code == 200

    revoke_response = client.post(f"/api-keys/{key_id}/revoke", headers=admin_headers)
    assert revoke_response.status_code == 200
    assert revoke_response.json()["revoked"] is True

    assert client.get("/auth/me", headers={"X-API-Key": raw_key}).status_code == 401


def test_invalid_api_key_returns_401(client):
    assert client.get("/auth/me", headers={"X-API-Key": "csk_not-a-real-key"}).status_code == 401


def test_api_key_last_used_at_updates_on_use(client, admin_headers):
    created = client.post("/api-keys", json={"name": "CI key"}, headers=admin_headers).json()
    assert created["last_used_at"] is None

    client.get("/auth/me", headers={"X-API-Key": created["key"]})

    listing = client.get("/api-keys", headers=admin_headers).json()["api_keys"]
    assert listing[0]["last_used_at"] is not None


def test_revoke_api_key_requires_admin(client, admin_headers, analyst_headers):
    created = client.post("/api-keys", json={"name": "CI key"}, headers=admin_headers).json()
    assert client.post(f"/api-keys/{created['id']}/revoke", headers=analyst_headers).status_code == 403


def test_api_keys_scoped_to_organization(client, admin_headers, other_org_admin_headers):
    client.post("/api-keys", json={"name": "our key"}, headers=admin_headers)

    own = client.get("/api-keys", headers=admin_headers).json()["api_keys"]
    other = client.get("/api-keys", headers=other_org_admin_headers).json()["api_keys"]
    assert len(own) == 1
    assert other == []


def test_role_change_creates_audit_entry(client, admin_headers, register_and_login, test_org):
    org_slug, _admin = test_org
    register_and_login("new-analyst@example.com", org_slug)
    users = client.get("/users", headers=admin_headers).json()
    target = next(u for u in users if u["email"] == "new-analyst@example.com")

    client.patch(f"/users/{target['id']}/role", json={"role": "analyst"}, headers=admin_headers)

    entries = client.get("/audit-log", headers=admin_headers).json()["entries"]
    entry = next(e for e in entries if e["action"] == "role_changed")
    assert entry["details"]["target_email"] == "new-analyst@example.com"
    assert entry["details"]["new_role"] == "analyst"


def test_audit_log_requires_admin(client, analyst_headers, viewer_headers):
    assert client.get("/audit-log", headers=analyst_headers).status_code == 403
    assert client.get("/audit-log", headers=viewer_headers).status_code == 403


def test_audit_log_scoped_to_organization(client, admin_headers, other_org_admin_headers):
    client.patch("/organizations/current", json={"name": "Renamed"}, headers=admin_headers)

    own = client.get("/audit-log", headers=admin_headers).json()["entries"]
    other = client.get("/audit-log", headers=other_org_admin_headers).json()["entries"]
    assert len(own) >= 1
    assert other == []


def test_organizations_current_requires_authentication(client):
    assert client.get("/organizations/current").status_code == 401


def test_bearer_auth_still_works_unaffected_by_api_key_support(client, admin_headers):
    # The get_current_user() refactor to support X-API-Key must not break
    # ordinary bearer-token auth for every other endpoint in the app.
    response = client.get("/auth/me", headers=admin_headers)
    assert response.status_code == 200
