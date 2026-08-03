from sqlalchemy.orm import Session

from app.db_models import Embedding, KnowledgeDocument
from app.rag import store_embedding

CHUNK_SIZE = 800
CHUNK_OVERLAP = 100

SAMPLE_DOCUMENTS = [
    (
        "Incident Response Playbook - Suspected Account Compromise",
        "When a user account shows signs of compromise (impossible travel, a login "
        "from a new country immediately followed by privilege changes, or multiple "
        "failed logins followed by a success), the first action is to disable the "
        "account, not just reset its password - a live session or an existing API "
        "token survives a password reset. Next, pull the account's last 24 hours of "
        "activity: what it accessed, what it changed, and whether it created any new "
        "credentials (API keys, OAuth grants, forwarding rules) that would outlive the "
        "original compromise. Only after containment and evidence collection should the "
        "account be re-enabled, and only with a forced password reset plus MFA "
        "re-enrollment, since the original MFA device may itself be compromised.",
    ),
    (
        "Common Attack Patterns - Lateral Movement",
        "Lateral movement is when an attacker who has already compromised one host uses "
        "it as a foothold to reach others on the same network, rather than attacking each "
        "host independently from outside. The most common technique is credential reuse: "
        "the same local administrator password across many machines, or a service account "
        "with excessive access, lets one compromised host unlock many more. Watch for a "
        "single host authenticating to an unusually large number of other hosts in a short "
        "window, or a service account logging in interactively (service accounts should "
        "only ever authenticate as a service, never interactively). Segmenting the network "
        "so a compromised workstation can't directly reach servers it has no business "
        "talking to is the most effective structural defense, more reliable than trying to "
        "catch every individual lateral-movement technique after the fact.",
    ),
    (
        "Alert Triage Priorities",
        "Not every alert deserves the same response speed. Alerts involving credential "
        "access (password dumping, token theft) or anything touching a domain "
        "controller or backup system should be treated as critical regardless of the "
        "detection engine's own severity score, because those two categories are where "
        "a contained incident turns into a full compromise. Alerts on a single "
        "already-known-noisy host (a scanner, a CI runner) can usually be triaged in "
        "batch rather than one at a time. When in doubt about priority, ask what the "
        "blast radius is if this alert is real and ignored for another hour - that "
        "question sorts alerts faster than any fixed severity table.",
    ),
]


def _chunk_text(text: str, chunk_size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP) -> list[str]:
    """Fixed-size sliding window over characters, not tokens - simple and
    good enough for the local sentence-transformers model's 256-token
    window, which chunk_size stays comfortably under for normal prose."""
    text = text.strip()
    if not text:
        return []
    chunks = []
    start = 0
    while start < len(text):
        end = start + chunk_size
        chunks.append(text[start:end].strip())
        if end >= len(text):
            break
        start = end - overlap
    return [c for c in chunks if c]


def ingest_document(db: Session, organization_id: int, title: str, text: str, filename: str | None, source: str, uploaded_by_user_id: int | None = None) -> KnowledgeDocument:
    chunks = _chunk_text(text)
    document = KnowledgeDocument(
        organization_id=organization_id, title=title, filename=filename, source=source,
        chunk_count=len(chunks), uploaded_by_user_id=uploaded_by_user_id,
    )
    db.add(document)
    db.flush()  # assigns document.id without committing yet

    for chunk in chunks:
        store_embedding(db, organization_id, "knowledge_chunk", document.id, chunk)

    db.commit()
    db.refresh(document)
    return document


def delete_document(db: Session, organization_id: int, document_id: int) -> bool:
    document = (
        db.query(KnowledgeDocument)
        .filter(KnowledgeDocument.organization_id == organization_id, KnowledgeDocument.id == document_id)
        .first()
    )
    if not document:
        return False

    db.query(Embedding).filter(
        Embedding.organization_id == organization_id,
        Embedding.content_type == "knowledge_chunk",
        Embedding.content_id == document_id,
    ).delete()
    db.delete(document)
    db.commit()
    return True


def seed_sample_documents(db: Session, organization_id: int) -> list[KnowledgeDocument]:
    """Idempotent: skips any sample title the org already has, so clicking
    'load samples' twice doesn't duplicate documents."""
    existing_titles = {
        title
        for (title,) in db.query(KnowledgeDocument.title).filter(
            KnowledgeDocument.organization_id == organization_id, KnowledgeDocument.source == "seed"
        )
    }
    created = []
    for title, text in SAMPLE_DOCUMENTS:
        if title in existing_titles:
            continue
        created.append(ingest_document(db, organization_id, title, text, filename=None, source="seed"))
    return created
