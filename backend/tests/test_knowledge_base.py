import io

from app.db_models import Embedding, KnowledgeDocument
from app.knowledge_base import SAMPLE_DOCUMENTS, _chunk_text, delete_document, ingest_document, seed_sample_documents


def test_chunk_text_splits_long_text_with_overlap():
    text = "a" * 2000
    chunks = _chunk_text(text, chunk_size=800, overlap=100)
    assert len(chunks) == 3
    # consecutive chunks overlap by exactly `overlap` characters
    assert chunks[0][-100:] == chunks[1][:100]


def test_chunk_text_short_text_is_one_chunk():
    assert _chunk_text("short document") == ["short document"]


def test_chunk_text_empty_or_whitespace_returns_no_chunks():
    assert _chunk_text("") == []
    assert _chunk_text("   \n  ") == []


def test_ingest_document_creates_document_and_embedding_rows(db_session, org_id):
    document = ingest_document(db_session, org_id, title="My Doc", text="a" * 1000, filename="doc.txt", source="upload")

    assert document.id is not None
    assert document.chunk_count == 2

    chunks = (
        db_session.query(Embedding)
        .filter(Embedding.organization_id == org_id, Embedding.content_type == "knowledge_chunk", Embedding.content_id == document.id)
        .all()
    )
    assert len(chunks) == 2


def test_delete_document_removes_document_and_its_chunks(db_session, org_id):
    document = ingest_document(db_session, org_id, title="To Delete", text="content here", filename=None, source="upload")

    assert delete_document(db_session, org_id, document.id) is True
    assert db_session.query(KnowledgeDocument).filter(KnowledgeDocument.id == document.id).first() is None
    assert (
        db_session.query(Embedding)
        .filter(Embedding.content_type == "knowledge_chunk", Embedding.content_id == document.id)
        .count()
        == 0
    )


def test_delete_document_returns_false_for_missing_or_other_org(db_session, org_id):
    assert delete_document(db_session, org_id, 999) is False


def test_delete_document_is_scoped_to_organization(db_session, org_id):
    from app.db_models import Organization

    other_org = Organization(name="Other Org", slug="other-org")
    db_session.add(other_org)
    db_session.commit()
    db_session.refresh(other_org)

    document = ingest_document(db_session, org_id, title="Mine", text="secret", filename=None, source="upload")

    assert delete_document(db_session, other_org.id, document.id) is False
    assert db_session.query(KnowledgeDocument).filter(KnowledgeDocument.id == document.id).first() is not None


def test_seed_sample_documents_creates_all_samples(db_session, org_id):
    created = seed_sample_documents(db_session, org_id)
    assert len(created) == len(SAMPLE_DOCUMENTS)
    assert all(d.source == "seed" for d in created)


def test_seed_sample_documents_is_idempotent(db_session, org_id):
    seed_sample_documents(db_session, org_id)
    second_run = seed_sample_documents(db_session, org_id)
    assert second_run == []
    assert db_session.query(KnowledgeDocument).filter(KnowledgeDocument.organization_id == org_id).count() == len(SAMPLE_DOCUMENTS)


def test_upload_list_and_delete_document_via_http(client, analyst_headers):
    file = io.BytesIO(b"Ransomware playbook: contain first, reset credentials second.")
    upload = client.post(
        "/knowledge-base/upload",
        params={"title": "My Playbook"},
        files={"file": ("playbook.txt", file, "text/plain")},
        headers=analyst_headers,
    )
    assert upload.status_code == 200
    doc = upload.json()
    assert doc["title"] == "My Playbook"
    assert doc["chunk_count"] == 1

    listing = client.get("/knowledge-base", headers=analyst_headers)
    assert listing.status_code == 200
    assert any(d["id"] == doc["id"] for d in listing.json()["documents"])

    delete = client.delete(f"/knowledge-base/{doc['id']}", headers=analyst_headers)
    assert delete.status_code == 200
    assert client.get("/knowledge-base", headers=analyst_headers).json()["documents"] == []


def test_upload_rejects_non_utf8_file(client, analyst_headers):
    file = io.BytesIO(b"\xff\xfe\x00\x01")
    response = client.post(
        "/knowledge-base/upload",
        files={"file": ("bad.bin", file, "application/octet-stream")},
        headers=analyst_headers,
    )
    assert response.status_code == 400


def test_upload_rejects_empty_file(client, analyst_headers):
    file = io.BytesIO(b"   ")
    response = client.post(
        "/knowledge-base/upload",
        files={"file": ("empty.txt", file, "text/plain")},
        headers=analyst_headers,
    )
    assert response.status_code == 400


def test_delete_missing_document_returns_404(client, analyst_headers):
    response = client.delete("/knowledge-base/999999", headers=analyst_headers)
    assert response.status_code == 404


def test_seed_samples_via_http(client, analyst_headers):
    response = client.post("/knowledge-base/seed-samples", headers=analyst_headers)
    assert response.status_code == 200
    assert len(response.json()["created"]) == len(SAMPLE_DOCUMENTS)


def test_uploaded_document_is_retrievable_via_chat_evidence(client, analyst_headers):
    """The whole point of reusing app/rag.py's Embedding table: /chat's
    unfiltered rag_search should surface knowledge_chunk content
    automatically, with no special-casing needed in the chat endpoint."""
    file = io.BytesIO(b"The SentraOps escalation policy requires paging the on-call lead within 15 minutes of any critical severity incident.")
    client.post(
        "/knowledge-base/upload",
        params={"title": "Escalation Policy"},
        files={"file": ("policy.txt", file, "text/plain")},
        headers=analyst_headers,
    )

    search = client.get("/rag/search", params={"q": "escalation policy on-call", "content_type": "knowledge_chunk"}, headers=analyst_headers)
    assert search.status_code == 200
    results = search.json()["results"]
    assert len(results) >= 1
    assert results[0]["content_type"] == "knowledge_chunk"
