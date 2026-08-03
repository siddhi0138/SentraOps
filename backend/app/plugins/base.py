from abc import ABC, abstractmethod


class ConnectorPlugin(ABC):
    """A pluggable log-source integration. A subclass wraps one real
    external API/feed and normalizes what it returns into raw items shaped
    for one of app/parsers/'s existing normalizers (`source_type` picks
    which one) - a connector is just a way to *produce* raw_items for
    app/ingestion.py.ingest(), the same entry point file uploads already
    use."""

    key: str
    display_name: str
    category: str
    source_type: str = "generic"
    config_fields: list[str] = []

    @abstractmethod
    def test_connection(self, config: dict) -> tuple[bool, str]:
        """Verifies the connector can actually reach its source with this
        config, without pulling/ingesting anything. Returns (ok, message)."""

    @abstractmethod
    def pull(self, config: dict) -> list[dict]:
        """Fetches recent raw items from the external source, shaped for
        `source_type`'s parser."""


class ResponseActionPlugin(ABC):
    """A pluggable executor for an approved ProposedAction. Distinct from
    ConnectorPlugin's direction: this pushes an already-human-approved
    action out to a real external system instead of pulling data in."""

    key: str
    display_name: str
    categories: list[str]
    config_fields: list[str] = []

    @abstractmethod
    def execute(self, config: dict, action: dict) -> tuple[bool, str]:
        """Carries out `action` (a ProposedAction.to_dict()) against the
        external system this config points at. Returns (success, message)."""
