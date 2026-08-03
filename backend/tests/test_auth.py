def test_first_registered_user_becomes_admin(client):
    response = client.post("/auth/register", json={"email": "first@example.com", "password": "Secret123!"})
    assert response.status_code == 200
    assert response.json()["role"] == "admin"


def test_second_registered_user_defaults_to_viewer(client):
    client.post("/auth/register", json={"email": "first@example.com", "password": "Secret123!"})
    response = client.post("/auth/register", json={"email": "second@example.com", "password": "Secret123!"})
    assert response.json()["role"] == "viewer"


def test_duplicate_email_registration_rejected(client):
    client.post("/auth/register", json={"email": "dupe@example.com", "password": "Secret123!"})
    response = client.post("/auth/register", json={"email": "dupe@example.com", "password": "Other123!"})
    assert response.status_code == 400


def test_login_with_wrong_password_rejected(client):
    client.post("/auth/register", json={"email": "user@example.com", "password": "Secret123!"})
    response = client.post("/auth/login", json={"email": "user@example.com", "password": "WrongPass!"})
    assert response.status_code == 401


def test_login_returns_access_and_refresh_tokens(client):
    client.post("/auth/register", json={"email": "user@example.com", "password": "Secret123!"})
    response = client.post("/auth/login", json={"email": "user@example.com", "password": "Secret123!"})
    body = response.json()
    assert "access_token" in body
    assert "refresh_token" in body


def test_me_returns_current_user(client):
    client.post("/auth/register", json={"email": "user@example.com", "password": "Secret123!"})
    login = client.post("/auth/login", json={"email": "user@example.com", "password": "Secret123!"})
    token = login.json()["access_token"]

    response = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["email"] == "user@example.com"


def test_refresh_token_issues_new_access_token(client):
    client.post("/auth/register", json={"email": "user@example.com", "password": "Secret123!"})
    login = client.post("/auth/login", json={"email": "user@example.com", "password": "Secret123!"})
    refresh_token = login.json()["refresh_token"]

    response = client.post("/auth/refresh", json={"refresh_token": refresh_token})
    assert response.status_code == 200
    assert "access_token" in response.json()


def test_access_token_rejected_as_refresh_token(client):
    client.post("/auth/register", json={"email": "user@example.com", "password": "Secret123!"})
    login = client.post("/auth/login", json={"email": "user@example.com", "password": "Secret123!"})
    access_token = login.json()["access_token"]

    response = client.post("/auth/refresh", json={"refresh_token": access_token})
    assert response.status_code == 401


def test_admin_can_list_and_promote_users(client, admin_headers, register_and_login):
    register_and_login("newbie@example.com")
    users = client.get("/users", headers=admin_headers).json()
    newbie = next(u for u in users if u["email"] == "newbie@example.com")
    assert newbie["role"] == "viewer"

    response = client.patch(
        f"/users/{newbie['id']}/role", json={"role": "analyst"}, headers=admin_headers
    )
    assert response.status_code == 200
    assert response.json()["role"] == "analyst"


def test_non_admin_cannot_list_users(client, viewer_headers):
    response = client.get("/users", headers=viewer_headers)
    assert response.status_code == 403


def test_promoted_viewer_gains_analyst_access_without_new_login(client, admin_headers, register_and_login):
    token = register_and_login("promoteme@example.com")
    headers = {"Authorization": f"Bearer {token}"}

    # before promotion: cannot ingest
    assert client.post("/ingest/generic", json={"logs": []}, headers=headers).status_code == 403

    users = client.get("/users", headers=admin_headers).json()
    user_id = next(u["id"] for u in users if u["email"] == "promoteme@example.com")
    client.patch(f"/users/{user_id}/role", json={"role": "analyst"}, headers=admin_headers)

    # role is looked up fresh from the DB on every request, so the existing
    # access token works immediately without re-authenticating.
    assert client.post("/ingest/generic", json={"logs": []}, headers=headers).status_code == 200
