import hashlib
import secrets

from sqlalchemy.orm import Session

from app.db_models import AuditLogEntry

API_KEY_PREFIX = "csk_"


def hash_api_key(raw_key: str) -> str:
    # SHA-256, not bcrypt - an API key is a high-entropy random secret, not
    # a human password, so there's no offline-guessing risk bcrypt's slow
    # hash defends against; a fast deterministic hash is the right tool
    # (and the standard approach for API-key storage).
    return hashlib.sha256(raw_key.encode()).hexdigest()


def generate_api_key() -> tuple[str, str, str]:
    """Returns (full_key_shown_once, key_hash, key_prefix). The full key is
    never stored anywhere - only its hash - so if this return value isn't
    captured and shown to the caller now, it's gone for good."""
    raw_key = f"{API_KEY_PREFIX}{secrets.token_urlsafe(32)}"
    return raw_key, hash_api_key(raw_key), raw_key[:12]


def record_audit(db: Session, organization_id: int, actor_email: str | None, action: str, details: dict | None = None) -> AuditLogEntry:
    """Appends one audit entry. Deliberately doesn't commit - callers add
    this as part of their own existing transaction (same pattern as
    AgentMessage rows added alongside their AgentRun), so an audit entry
    only ever exists if the action it describes actually committed too."""
    entry = AuditLogEntry(organization_id=organization_id, actor_email=actor_email, action=action, details=details or {})
    db.add(entry)
    return entry
