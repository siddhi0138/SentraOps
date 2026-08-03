from unittest.mock import patch

from app.ai import _explain_system_prompt
from app.marketplace import (
    get_installed_prompt_addition,
    install_playbook,
    list_installed,
    list_playbooks,
    uninstall_playbook,
)


def test_list_playbooks_returns_seeded_catalog(db_session):
    playbooks = list_playbooks(db_session)
    assert len(playbooks) == 5
    keys = {p.key for p in playbooks}
    assert keys == {"ransomware_response", "insider_threat", "pci_dss_focus", "hipaa_focus", "board_brief"}


def test_install_and_list_installed(db_session, org_id):
    playbook = list_playbooks(db_session)[0]
    assert list_installed(db_session, org_id) == []

    install_playbook(db_session, org_id, playbook.id)
    db_session.commit()

    installed = list_installed(db_session, org_id)
    assert len(installed) == 1
    assert installed[0].id == playbook.id


def test_install_is_idempotent(db_session, org_id):
    playbook = list_playbooks(db_session)[0]
    install_playbook(db_session, org_id, playbook.id)
    db_session.commit()
    install_playbook(db_session, org_id, playbook.id)
    db_session.commit()

    assert len(list_installed(db_session, org_id)) == 1


def test_uninstall_removes_install(db_session, org_id):
    playbook = list_playbooks(db_session)[0]
    install_playbook(db_session, org_id, playbook.id)
    db_session.commit()

    assert uninstall_playbook(db_session, org_id, playbook.id) is True
    assert list_installed(db_session, org_id) == []


def test_uninstall_nonexistent_returns_false(db_session, org_id):
    playbook = list_playbooks(db_session)[0]
    assert uninstall_playbook(db_session, org_id, playbook.id) is False


def test_installs_scoped_to_organization(db_session, org_id):
    from app.db_models import Organization

    other_org = Organization(name="Other", slug="other-marketplace-org")
    db_session.add(other_org)
    db_session.commit()
    db_session.refresh(other_org)

    playbook = list_playbooks(db_session)[0]
    install_playbook(db_session, org_id, playbook.id)
    db_session.commit()

    assert len(list_installed(db_session, org_id)) == 1
    assert list_installed(db_session, other_org.id) == []


def test_get_installed_prompt_addition_empty_when_none_installed(db_session, org_id):
    assert get_installed_prompt_addition(db_session, org_id) == ""


def test_get_installed_prompt_addition_concatenates_installed_playbooks(db_session, org_id):
    playbooks = list_playbooks(db_session)
    install_playbook(db_session, org_id, playbooks[0].id)
    install_playbook(db_session, org_id, playbooks[1].id)
    db_session.commit()

    guidance = get_installed_prompt_addition(db_session, org_id)
    assert playbooks[0].prompt_addition in guidance
    assert playbooks[1].prompt_addition in guidance


def test_explain_system_prompt_includes_playbook_guidance():
    prompt = _explain_system_prompt("analyst", playbook_guidance="Extra board-focused instruction.")
    assert "Extra board-focused instruction." in prompt


def test_explain_system_prompt_omits_guidance_block_when_empty():
    with_guidance = _explain_system_prompt("analyst", playbook_guidance="X")
    without_guidance = _explain_system_prompt("analyst", playbook_guidance="")
    assert "X" in with_guidance
    assert "X" not in without_guidance


def test_list_marketplace_playbooks_endpoint(client, viewer_headers):
    response = client.get("/marketplace/playbooks", headers=viewer_headers)
    assert response.status_code == 200
    playbooks = response.json()["playbooks"]
    assert len(playbooks) == 5
    assert all(p["installed"] is False for p in playbooks)


def test_install_requires_admin(client, analyst_headers, viewer_headers, admin_headers):
    playbook_id = client.get("/marketplace/playbooks", headers=viewer_headers).json()["playbooks"][0]["id"]

    assert client.post(f"/marketplace/playbooks/{playbook_id}/install", headers=viewer_headers).status_code == 403
    assert client.post(f"/marketplace/playbooks/{playbook_id}/install", headers=analyst_headers).status_code == 403

    response = client.post(f"/marketplace/playbooks/{playbook_id}/install", headers=admin_headers)
    assert response.status_code == 200
    assert response.json()["installed"] is True

    listing = client.get("/marketplace/playbooks", headers=admin_headers).json()["playbooks"]
    assert next(p for p in listing if p["id"] == playbook_id)["installed"] is True


def test_uninstall_requires_admin(client, admin_headers, analyst_headers):
    playbook_id = client.get("/marketplace/playbooks", headers=admin_headers).json()["playbooks"][0]["id"]
    client.post(f"/marketplace/playbooks/{playbook_id}/install", headers=admin_headers)

    assert client.post(f"/marketplace/playbooks/{playbook_id}/uninstall", headers=analyst_headers).status_code == 403

    response = client.post(f"/marketplace/playbooks/{playbook_id}/uninstall", headers=admin_headers)
    assert response.status_code == 200
    assert response.json()["installed"] is False


def test_install_unknown_playbook_returns_404(client, admin_headers):
    assert client.post("/marketplace/playbooks/99999/install", headers=admin_headers).status_code == 404


def test_installs_scoped_to_organization_via_api(client, admin_headers, other_org_admin_headers):
    playbook_id = client.get("/marketplace/playbooks", headers=admin_headers).json()["playbooks"][0]["id"]
    client.post(f"/marketplace/playbooks/{playbook_id}/install", headers=admin_headers)

    own = client.get("/marketplace/playbooks", headers=admin_headers).json()["playbooks"]
    other = client.get("/marketplace/playbooks", headers=other_org_admin_headers).json()["playbooks"]
    assert next(p for p in own if p["id"] == playbook_id)["installed"] is True
    assert next(p for p in other if p["id"] == playbook_id)["installed"] is False


def test_marketplace_endpoints_require_authentication(client):
    assert client.get("/marketplace/playbooks").status_code == 401
    assert client.post("/marketplace/playbooks/1/install").status_code == 401


def test_explain_endpoint_passes_installed_playbook_guidance(client, analyst_headers, admin_headers):
    playbook = client.get("/marketplace/playbooks", headers=admin_headers).json()["playbooks"][0]
    client.post(f"/marketplace/playbooks/{playbook['id']}/install", headers=admin_headers)

    client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    client.post("/correlate", headers=analyst_headers)
    incident_id = client.get("/incidents", headers=analyst_headers).json()["incidents"][0]["id"]

    fake_explanation = {
        "explanation": "x",
        "timeline_narrative": "x",
        "attack_type": "x",
        "affected_user": "x",
        "affected_assets": "x",
        "impact": "x",
    }
    with patch("app.main.explain_incident", return_value=fake_explanation) as mock_explain:
        response = client.get(f"/incidents/{incident_id}/explain", headers=analyst_headers)

    assert response.status_code == 200
    assert mock_explain.call_args.kwargs["playbook_guidance"] != ""
