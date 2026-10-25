from unittest.mock import MagicMock, patch

import pytest
from kubernetes.client.exceptions import ApiException
from kubernetes.config import ConfigException

from app import bas


def test_techniques_catalog_has_required_fields():
    assert len(bas.TECHNIQUES) > 0
    for tid, technique in bas.TECHNIQUES.items():
        assert technique["name"]
        assert technique["category"]
        assert technique["severity"] in {"low", "medium", "high", "critical"}
        assert technique["command"]
        assert tid.startswith("T")


def test_run_technique_rejects_unknown_id():
    with pytest.raises(ValueError, match="Unknown technique"):
        bas.run_technique(1, "T9999")


def test_techniques_catalog_has_more_than_one_category():
    # The whole point of pick_random_campaign() is variety - if everything
    # were "discovery" there'd be nothing else to sample from.
    categories = {t["category"] for t in bas.TECHNIQUES.values()}
    assert len(categories) >= 4


def test_pick_random_campaign_includes_discovery_and_other_techniques():
    campaign = bas.pick_random_campaign()
    categories = {bas.TECHNIQUES[tid]["category"] for tid in campaign}
    assert "discovery" in categories
    assert len(categories) >= 2  # at least one non-discovery technique too
    assert len(campaign) == len(set(campaign))  # no duplicates


def test_pick_random_campaign_varies_across_calls():
    # Not a strict guarantee (a truly unlucky RNG could repeat), but with
    # this many techniques to sample from, 20 calls all matching would mean
    # the randomization isn't actually random.
    campaigns = {tuple(sorted(bas.pick_random_campaign())) for _ in range(20)}
    assert len(campaigns) > 1


def test_pick_random_campaign_only_returns_known_technique_ids():
    campaign = bas.pick_random_campaign()
    assert all(tid in bas.TECHNIQUES for tid in campaign)


def test_load_k8s_config_raises_not_configured_when_no_cluster_access():
    with patch("app.bas.config.load_incluster_config", side_effect=ConfigException("no in-cluster config")):
        with patch("app.bas.config.load_kube_config", side_effect=ConfigException("no kubeconfig")):
            with pytest.raises(bas.BasNotConfiguredError):
                bas._load_k8s_config()


def test_run_technique_raises_not_configured_without_cluster_access(monkeypatch):
    monkeypatch.setattr("app.bas._current_namespace", lambda: "default")
    with patch("app.bas.config.load_incluster_config", side_effect=ConfigException("x")):
        with patch("app.bas.config.load_kube_config", side_effect=ConfigException("x")):
            with pytest.raises(bas.BasNotConfiguredError):
                bas.run_technique(1, "T1082")


def _fake_pod(phase: str):
    pod = MagicMock()
    pod.status.phase = phase
    return pod


def test_ensure_target_pod_creates_pod_when_missing(monkeypatch):
    monkeypatch.setattr("app.bas._current_namespace", lambda: "default")
    fake_v1 = MagicMock()
    fake_v1.read_namespaced_pod.side_effect = [ApiException(status=404, reason="Not Found"), _fake_pod("Running")]

    with patch("app.bas.config.load_incluster_config"):
        with patch("app.bas.client.CoreV1Api", return_value=fake_v1):
            namespace, pod_name = bas.ensure_target_pod(organization_id=42)

    assert namespace == "default"
    assert pod_name == "sentraops-bas-target-42"
    fake_v1.create_namespaced_pod.assert_called_once()


def test_ensure_target_pod_reuses_existing_pod(monkeypatch):
    monkeypatch.setattr("app.bas._current_namespace", lambda: "default")
    fake_v1 = MagicMock()
    fake_v1.read_namespaced_pod.return_value = _fake_pod("Running")

    with patch("app.bas.config.load_incluster_config"):
        with patch("app.bas.client.CoreV1Api", return_value=fake_v1):
            bas.ensure_target_pod(organization_id=42)

    fake_v1.create_namespaced_pod.assert_not_called()


def test_ensure_target_pod_propagates_non_404_api_errors(monkeypatch):
    monkeypatch.setattr("app.bas._current_namespace", lambda: "default")
    fake_v1 = MagicMock()
    fake_v1.read_namespaced_pod.side_effect = ApiException(status=403, reason="Forbidden")

    with patch("app.bas.config.load_incluster_config"):
        with patch("app.bas.client.CoreV1Api", return_value=fake_v1):
            with pytest.raises(ApiException):
                bas.ensure_target_pod(organization_id=42)


def test_exec_in_pod_parses_output_and_exit_code():
    with patch("app.bas.stream", return_value="line one\nline two\n__EXIT:0\n"):
        output, exit_code = bas._exec_in_pod("ns", "pod", "sh -c 'echo hi'")

    assert output == "line one\nline two"
    assert exit_code == 0


def test_exec_in_pod_defaults_exit_code_when_marker_missing():
    with patch("app.bas.stream", return_value="no marker here"):
        output, exit_code = bas._exec_in_pod("ns", "pod", "sh -c 'echo hi'")

    assert exit_code == 1


def test_run_technique_returns_normalized_event(monkeypatch):
    monkeypatch.setattr("app.bas._current_namespace", lambda: "default")
    fake_v1 = MagicMock()
    fake_v1.read_namespaced_pod.return_value = _fake_pod("Running")

    with patch("app.bas.config.load_incluster_config"):
        with patch("app.bas.client.CoreV1Api", return_value=fake_v1):
            with patch("app.bas.stream", return_value="Linux abc123\n__EXIT:0\n"):
                event = bas.run_technique(organization_id=7, technique_id="T1082")

    assert event["host"] == "sentraops-bas-target-7"
    assert event["event_type"] == "bas_t1082"
    assert event["severity"] == "low"
    assert "T1082" in event["message"]
    assert "exit 0" in event["message"]
    assert "Linux abc123" in event["message"]


def test_run_campaign_runs_each_technique(monkeypatch):
    monkeypatch.setattr("app.bas._current_namespace", lambda: "default")
    fake_v1 = MagicMock()
    fake_v1.read_namespaced_pod.return_value = _fake_pod("Running")

    with patch("app.bas.config.load_incluster_config"):
        with patch("app.bas.client.CoreV1Api", return_value=fake_v1):
            with patch("app.bas.stream", return_value="ok\n__EXIT:0\n"):
                events = bas.run_campaign(organization_id=7, technique_ids=["T1082", "T1033"])

    assert len(events) == 2
    assert {e["event_type"] for e in events} == {"bas_t1082", "bas_t1033"}


def test_teardown_target_pod_returns_true_when_deleted(monkeypatch):
    monkeypatch.setattr("app.bas._current_namespace", lambda: "default")
    fake_v1 = MagicMock()

    with patch("app.bas.config.load_incluster_config"):
        with patch("app.bas.client.CoreV1Api", return_value=fake_v1):
            assert bas.teardown_target_pod(organization_id=7) is True
    fake_v1.delete_namespaced_pod.assert_called_once()


def test_teardown_target_pod_returns_false_when_not_found(monkeypatch):
    monkeypatch.setattr("app.bas._current_namespace", lambda: "default")
    fake_v1 = MagicMock()
    fake_v1.delete_namespaced_pod.side_effect = ApiException(status=404, reason="Not Found")

    with patch("app.bas.config.load_incluster_config"):
        with patch("app.bas.client.CoreV1Api", return_value=fake_v1):
            assert bas.teardown_target_pod(organization_id=7) is False


def test_list_bas_techniques_endpoint(client, analyst_headers):
    response = client.get("/bas/techniques", headers=analyst_headers)
    assert response.status_code == 200
    techniques = response.json()["techniques"]
    assert len(techniques) == len(bas.TECHNIQUES)
    assert {t["id"] for t in techniques} == set(bas.TECHNIQUES)


def test_run_bas_campaign_rejects_unknown_technique(client, analyst_headers):
    response = client.post("/bas/run", json={"technique_ids": ["T9999"]}, headers=analyst_headers)
    assert response.status_code == 400


def test_run_bas_campaign_returns_503_when_not_configured(client, analyst_headers):
    with patch("app.main.bas.run_campaign", side_effect=bas.BasNotConfiguredError("no cluster access")):
        response = client.post("/bas/run", json={"technique_ids": ["T1082"]}, headers=analyst_headers)
    assert response.status_code == 503


def test_run_bas_campaign_returns_502_on_unexpected_cluster_error(client, analyst_headers):
    with patch("app.main.bas.run_campaign", side_effect=RuntimeError("pod scheduling failed")):
        response = client.post("/bas/run", json={"technique_ids": ["T1082"]}, headers=analyst_headers)
    assert response.status_code == 502
    assert "pod scheduling failed" in response.json()["detail"]


def test_run_bas_campaign_ingests_real_events(client, analyst_headers):
    fake_event = {
        "timestamp": "2026-07-31T00:00:00+00:00", "host": "sentraops-bas-target-1", "username": "bas-simulation",
        "event_type": "bas_t1082", "severity": "low", "message": "[BAS] T1082 System Information Discovery - exit 0: Linux",
    }
    with patch("app.main.bas.run_campaign", return_value=[fake_event]):
        response = client.post("/bas/run", json={"technique_ids": ["T1082"]}, headers=analyst_headers)

    assert response.status_code == 200
    body = response.json()
    assert body == {"ran": 1, "ingested": 1, "skipped": 0}


def test_run_bas_campaign_requires_operational_role(client, viewer_headers):
    response = client.post("/bas/run", json={"technique_ids": ["T1082"]}, headers=viewer_headers)
    assert response.status_code == 403


def test_teardown_bas_target_endpoint(client, analyst_headers):
    with patch("app.main.bas.teardown_target_pod", return_value=True):
        response = client.delete("/bas/target", headers=analyst_headers)
    assert response.status_code == 200
    assert response.json() == {"deleted": True}
