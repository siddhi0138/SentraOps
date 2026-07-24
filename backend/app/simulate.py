import json
from pathlib import Path
from typing import Callable

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "samples"


def _load_json(name: str) -> list:
    return json.loads((DATA_DIR / name).read_text())


def _load_lines(name: str) -> list[str]:
    return [line for line in (DATA_DIR / name).read_text().splitlines() if line.strip()]


def _phishing_ransomware_scenario() -> dict[str, list]:
    """Same incident as the milestone-1 demo, reconstructed as the raw,
    native-format logs a real SOC would actually ingest (Windows Security
    log, firewall allow/deny log, SSH/sudo syslog) instead of one
    pre-normalized JSON file."""
    return {
        "windows": _load_json("windows_events.json"),
        "firewall": _load_json("firewall.json"),
        "syslog": _load_lines("syslog.log"),
    }


SCENARIOS: dict[str, Callable[[], dict[str, list]]] = {
    "phishing_ransomware": _phishing_ransomware_scenario,
}


def get_scenario(name: str) -> dict[str, list]:
    try:
        return SCENARIOS[name]()
    except KeyError:
        raise ValueError(f"Unknown scenario '{name}'. Supported: {sorted(SCENARIOS)}")
