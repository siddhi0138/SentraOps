import json
from pathlib import Path

from app.models import LogEvent
from app.pipeline import SecurityPipeline

SAMPLE_LOGS_PATH = Path(__file__).resolve().parent / "data" / "sample_logs.json"


def main() -> None:
    raw_logs = json.loads(SAMPLE_LOGS_PATH.read_text())
    logs = [LogEvent(**entry) for entry in raw_logs]

    incident = SecurityPipeline().run(logs)
    print(incident.report)


if __name__ == "__main__":
    main()
