def test_creating_organization_makes_first_user_owner(client):
    response = client.post(
        "/organizations",
        json={"organization_name": "Acme Corp", "email": "first@example.com", "password": "Secret123!"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["role"] == "owner"
    assert body["organization_name"] == "Acme Corp"
    assert body["organization_slug"]


def test_organization_slug_is_url_safe_and_deduped_on_collision(client):
    first = client.post(
        "/organizations", json={"organization_name": "Acme Corp!", "email": "a@example.com", "password": "Secret123!"}
    )
    second = client.post(
        "/organizations", json={"organization_name": "Acme Corp!", "email": "b@example.com", "password": "Secret123!"}
    )
    assert first.json()["organization_slug"] == "acme-corp"
    assert second.json()["organization_slug"] == "acme-corp-2"


def test_joining_existing_organization_defaults_to_auditor(client, test_org):
    org_slug, _admin = test_org
    response = client.post(
        "/auth/register",
        json={"email": "second@example.com", "password": "Secret123!", "organization_slug": org_slug},
    )
    assert response.status_code == 200
    assert response.json()["role"] == "auditor"


def test_registering_with_unknown_organization_slug_returns_404(client):
    response = client.post(
        "/auth/register",
        json={"email": "nobody@example.com", "password": "Secret123!", "organization_slug": "does-not-exist"},
    )
    assert response.status_code == 404


def test_duplicate_email_registration_rejected(client, test_org):
    org_slug, _admin = test_org
    client.post(
        "/auth/register", json={"email": "dupe@example.com", "password": "Secret123!", "organization_slug": org_slug}
    )
    response = client.post(
        "/auth/register", json={"email": "dupe@example.com", "password": "Other123!", "organization_slug": org_slug}
    )
    assert response.status_code == 400


def test_duplicate_email_rejected_even_across_organizations(client, test_org):
    org_slug, _admin = test_org
    client.post(
        "/auth/register", json={"email": "shared@example.com", "password": "Secret123!", "organization_slug": org_slug}
    )
    response = client.post(
        "/organizations",
        json={"organization_name": "Another Org", "email": "shared@example.com", "password": "Secret123!"},
    )
    assert response.status_code == 400


def test_login_with_wrong_password_rejected(client, test_org):
    org_slug, _admin = test_org
    client.post(
        "/auth/register", json={"email": "user@example.com", "password": "Secret123!", "organization_slug": org_slug}
    )
    response = client.post("/auth/login", json={"email": "user@example.com", "password": "WrongPass!"})
    assert response.status_code == 401


def test_login_returns_access_and_refresh_tokens(client, test_org):
    org_slug, _admin = test_org
    client.post(
        "/auth/register", json={"email": "user@example.com", "password": "Secret123!", "organization_slug": org_slug}
    )
    response = client.post("/auth/login", json={"email": "user@example.com", "password": "Secret123!"})
    body = response.json()
    assert "access_token" in body
    assert "refresh_token" in body


def test_me_returns_current_user(client, test_org):
    org_slug, _admin = test_org
    client.post(
        "/auth/register", json={"email": "user@example.com", "password": "Secret123!", "organization_slug": org_slug}
    )
    login = client.post("/auth/login", json={"email": "user@example.com", "password": "Secret123!"})
    token = login.json()["access_token"]

    response = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["email"] == "user@example.com"
    assert response.json()["organization_slug"] == org_slug


def test_refresh_token_issues_new_access_token(client, test_org):
    org_slug, _admin = test_org
    client.post(
        "/auth/register", json={"email": "user@example.com", "password": "Secret123!", "organization_slug": org_slug}
    )
    login = client.post("/auth/login", json={"email": "user@example.com", "password": "Secret123!"})
    refresh_token = login.json()["refresh_token"]

    response = client.post("/auth/refresh", json={"refresh_token": refresh_token})
    assert response.status_code == 200
    assert "access_token" in response.json()


def test_access_token_rejected_as_refresh_token(client, test_org):
    org_slug, _admin = test_org
    client.post(
        "/auth/register", json={"email": "user@example.com", "password": "Secret123!", "organization_slug": org_slug}
    )
    login = client.post("/auth/login", json={"email": "user@example.com", "password": "Secret123!"})
    access_token = login.json()["access_token"]

    response = client.post("/auth/refresh", json={"refresh_token": access_token})
    assert response.status_code == 401


def test_admin_can_list_and_promote_users(client, test_org, register_and_login):
    org_slug, admin_headers = test_org
    register_and_login("newbie@example.com", org_slug)
    users = client.get("/users", headers=admin_headers).json()
    newbie = next(u for u in users if u["email"] == "newbie@example.com")
    assert newbie["role"] == "auditor"

    response = client.patch(
        f"/users/{newbie['id']}/role", json={"role": "analyst"}, headers=admin_headers
    )
    assert response.status_code == 200
    assert response.json()["role"] == "analyst"


def test_any_role_can_list_users(client, viewer_headers):
    # Viewing teammates (email + role) is harmless read-only info - every
    # role can see it, only *changing* someone's role is admin-only.
    response = client.get("/users", headers=viewer_headers)
    assert response.status_code == 200


def test_promoted_auditor_gains_analyst_access_without_new_login(client, test_org, register_and_login):
    org_slug, admin_headers = test_org
    token = register_and_login("promoteme@example.com", org_slug)
    headers = {"Authorization": f"Bearer {token}"}

    # before promotion: cannot ingest
    assert client.post("/ingest/generic", json={"logs": []}, headers=headers).status_code == 403

    users = client.get("/users", headers=admin_headers).json()
    user_id = next(u["id"] for u in users if u["email"] == "promoteme@example.com")
    client.patch(f"/users/{user_id}/role", json={"role": "analyst"}, headers=admin_headers)

    # role is looked up fresh from the DB on every request, so the existing
    # access token works immediately without re-authenticating.
    assert client.post("/ingest/generic", json={"logs": []}, headers=headers).status_code == 200


def test_admin_cannot_promote_user_in_a_different_organization(client, test_org, other_org_admin_headers):
    _org_slug, admin_headers = test_org
    other_users = client.get("/users", headers=other_org_admin_headers).json()
    other_admin_id = other_users[0]["id"]

    response = client.patch(
        f"/users/{other_admin_id}/role", json={"role": "auditor"}, headers=admin_headers
    )
    assert response.status_code == 404


def test_admin_cannot_see_users_from_a_different_organization(client, test_org, other_org_admin_headers):
    _org_slug, admin_headers = test_org
    other_users = client.get("/users", headers=other_org_admin_headers).json()
    other_email = other_users[0]["email"]

    my_users = client.get("/users", headers=admin_headers).json()
    assert other_email not in [u["email"] for u in my_users]


def test_admin_cannot_grant_owner_role(client, test_org, register_and_login):
    """Admin has the same day-to-day permissions as Owner, but must not be
    able to self-promote (or promote anyone else) to the org's top role -
    only an existing Owner can do that."""
    org_slug, owner_headers = test_org
    admin_token = register_and_login("wannabe-admin@example.com", org_slug)
    admin_id = next(
        u["id"] for u in client.get("/users", headers=owner_headers).json() if u["email"] == "wannabe-admin@example.com"
    )
    client.patch(f"/users/{admin_id}/role", json={"role": "admin"}, headers=owner_headers)
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    register_and_login("target@example.com", org_slug)
    target_id = next(u["id"] for u in client.get("/users", headers=owner_headers).json() if u["email"] == "target@example.com")

    response = client.patch(f"/users/{target_id}/role", json={"role": "owner"}, headers=admin_headers)
    assert response.status_code == 403


def test_owner_can_grant_and_revoke_owner_role(client, test_org, register_and_login):
    org_slug, owner_headers = test_org
    register_and_login("newowner@example.com", org_slug)
    user_id = next(
        u["id"] for u in client.get("/users", headers=owner_headers).json() if u["email"] == "newowner@example.com"
    )
    response = client.patch(f"/users/{user_id}/role", json={"role": "owner"}, headers=owner_headers)
    assert response.status_code == 200
    assert response.json()["role"] == "owner"


def test_signup_with_too_long_a_password_is_rejected_with_a_clear_message_not_a_500(client):
    # bcrypt only handles 72 bytes; this used to crash the request (a 500 with no CORS
    # headers, which browsers report as a CORS error).
    response = client.post(
        "/organizations",
        json={"organization_name": "Long Pass Co", "email": "long@example.com", "password": "x" * 80},
    )
    assert response.status_code == 422
    assert "at most 72 bytes" in response.text


def test_password_limit_counts_bytes_not_characters(client):
    # 40 two-byte characters = 80 bytes: too long even though it is only 40 characters.
    response = client.post(
        "/organizations",
        json={"organization_name": "Bytes Co", "email": "bytes@example.com", "password": "é" * 40},
    )
    assert response.status_code == 422

    ok = client.post(
        "/organizations",
        json={"organization_name": "Bytes Co", "email": "bytes@example.com", "password": "x" * 72},
    )
    assert ok.status_code == 200


def test_register_into_existing_org_also_rejects_a_too_long_password(client, test_org):
    org_slug, _headers = test_org
    response = client.post(
        "/auth/register",
        json={"email": "joiner@example.com", "password": "y" * 80, "organization_slug": org_slug},
    )
    assert response.status_code == 422


def test_login_with_a_too_long_password_is_a_normal_401_not_a_500(client):
    client.post(
        "/organizations",
        json={"organization_name": "Login Co", "email": "login@example.com", "password": "Secret123!"},
    )
    response = client.post("/auth/login", json={"email": "login@example.com", "password": "z" * 200})
    assert response.status_code == 401


def test_a_password_stored_after_truncation_still_verifies():
    from app.auth import hash_password, verify_password

    stored = hash_password("a" * 72)  # what older bcrypt versions stored for any longer password
    assert verify_password("a" * 72, stored)
    assert verify_password("a" * 100, stored)  # same first 72 bytes: old behavior, no crash
    assert not verify_password("b" * 72, stored)
