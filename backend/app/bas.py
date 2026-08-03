import time
from datetime import datetime, timezone
from pathlib import Path

from kubernetes import client, config
from kubernetes.client.rest import ApiException
from kubernetes.stream import stream

TARGET_IMAGE = "alpine:3.19"
_NAMESPACE_FILE = Path("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
POD_READY_TIMEOUT_SECONDS = 30


class BasNotConfiguredError(Exception):
    """No Kubernetes API access available - e.g. running under plain
    `docker compose` locally instead of the real Helm/Kind deployment.
    Deliberately has no fallback: unlike VirusTotal/AbuseIPDB (real data
    vs. a local demo dataset - either is honest), there's no safe "fake"
    version of *actually executing a technique* - it either runs for real
    against a real sandboxed pod, or it doesn't run at all."""


# Real, safe-by-construction MITRE ATT&CK techniques: read-only discovery,
# plus one simulated benign C2-style outbound call and one harmless
# obfuscation example. Nothing here modifies the target, escalates
# privilege, or reaches outside example.com's well-known documentation
# domain. Commands are limited to what busybox/alpine ships with, no
# package install step (smaller attack surface, faster pod start).
TECHNIQUES: dict[str, dict] = {
    "T1082": {
        "name": "System Information Discovery",
        "category": "discovery",
        "severity": "low",
        "command": "sh -c 'uname -a; cat /etc/os-release'",
    },
    "T1033": {
        "name": "System Owner/User Discovery",
        "category": "discovery",
        "severity": "low",
        "command": "sh -c 'whoami; id'",
    },
    "T1057": {
        "name": "Process Discovery",
        "category": "discovery",
        "severity": "medium",
        "command": "sh -c 'ps aux'",
    },
    "T1016": {
        "name": "System Network Configuration Discovery",
        "category": "discovery",
        "severity": "medium",
        "command": "sh -c 'hostname -i 2>/dev/null; cat /etc/hosts'",
    },
    "T1105": {
        "name": "Ingress Tool Transfer (simulated - benign target)",
        "category": "command-and-control",
        "severity": "high",
        "command": "sh -c \"wget -q -O /dev/null -S https://example.com 2>&1 | grep 'HTTP/'\"",
    },
    "T1027": {
        "name": "Obfuscated Files or Information (base64)",
        "category": "defense-evasion",
        "severity": "high",
        "command": "sh -c \"echo whoami | base64\"",
    },
}


def _load_k8s_config() -> None:
    try:
        config.load_incluster_config()
    except config.ConfigException:
        try:
            config.load_kube_config()
        except config.ConfigException:
            raise BasNotConfiguredError(
                "No Kubernetes API access available - BAS only runs when SentraOps itself is deployed to a "
                "cluster (see deploy/helm/), not under plain `docker compose up`."
            )


def _current_namespace() -> str:
    if _NAMESPACE_FILE.exists():
        return _NAMESPACE_FILE.read_text().strip()
    return "default"


def _target_pod_name(organization_id: int) -> str:
    return f"sentraops-bas-target-{organization_id}"


def ensure_target_pod(organization_id: int) -> tuple[str, str]:
    """Creates the org's BAS target pod if it doesn't already exist
    (reused across runs, not recreated per-technique) and waits for it to
    reach Running. Returns (namespace, pod_name)."""
    _load_k8s_config()
    v1 = client.CoreV1Api()
    namespace = _current_namespace()
    pod_name = _target_pod_name(organization_id)

    try:
        v1.read_namespaced_pod(pod_name, namespace)
    except ApiException as exc:
        if exc.status != 404:
            raise
        pod = client.V1Pod(
            metadata=client.V1ObjectMeta(
                name=pod_name,
                labels={"app.kubernetes.io/component": "bas-target", "sentraops.io/organization-id": str(organization_id)},
            ),
            spec=client.V1PodSpec(
                containers=[client.V1Container(name="target", image=TARGET_IMAGE, command=["sleep", "infinity"])],
                restart_policy="Never",
            ),
        )
        v1.create_namespaced_pod(namespace, pod)

    deadline = time.monotonic() + POD_READY_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        status = v1.read_namespaced_pod(pod_name, namespace).status
        if status.phase == "Running":
            return namespace, pod_name
        time.sleep(1)
    raise BasNotConfiguredError(f"BAS target pod didn't reach Running within {POD_READY_TIMEOUT_SECONDS}s")


def _exec_in_pod(namespace: str, pod_name: str, command: str) -> tuple[str, int]:
    """Real `kubectl exec`-equivalent via the API server's pods/exec
    subresource. Returns (combined output, best-effort exit code) - the
    stream API doesn't give a clean separate exit code without the
    heavier WSClient protocol, so a trailing marker command reports it."""
    full_command = ["sh", "-c", f"{command}; echo __EXIT:$?"]
    output = stream(
        client.CoreV1Api().connect_get_namespaced_pod_exec,
        pod_name, namespace,
        command=full_command,
        stderr=True, stdin=False, stdout=True, tty=False,
    )
    exit_code = 1
    if "__EXIT:" in output:
        output, _, marker = output.rpartition("__EXIT:")
        try:
            exit_code = int(marker.strip().splitlines()[0])
        except (ValueError, IndexError):
            pass
    return output.strip(), exit_code


def run_technique(organization_id: int, technique_id: str) -> dict:
    """Executes one real technique's command inside the org's sandboxed
    target pod and returns a normalized event dict (same shape
    app/parsers/generic.py expects) ready for app/ingestion.py.ingest()."""
    technique = TECHNIQUES.get(technique_id)
    if not technique:
        raise ValueError(f"Unknown technique '{technique_id}'. Supported: {sorted(TECHNIQUES)}")

    namespace, pod_name = ensure_target_pod(organization_id)
    output, exit_code = _exec_in_pod(namespace, pod_name, technique["command"])

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": pod_name,
        "username": "bas-simulation",
        "event_type": f"bas_{technique_id.lower()}",
        "severity": technique["severity"],
        "message": (
            f"[BAS] {technique_id} {technique['name']} ({technique['category']}) - "
            f"exit {exit_code}: {output[:400]}"
        ),
    }


def run_campaign(organization_id: int, technique_ids: list[str]) -> list[dict]:
    return [run_technique(organization_id, tid) for tid in technique_ids]


def teardown_target_pod(organization_id: int) -> bool:
    _load_k8s_config()
    v1 = client.CoreV1Api()
    namespace = _current_namespace()
    pod_name = _target_pod_name(organization_id)
    try:
        v1.delete_namespaced_pod(pod_name, namespace)
    except ApiException as exc:
        if exc.status == 404:
            return False
        raise
    return True
