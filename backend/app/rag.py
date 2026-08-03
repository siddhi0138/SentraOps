from sqlalchemy.orm import Session

from app.db_models import Embedding
from app.embeddings import embed_text


def store_embedding(db: Session, content_type: str, content_id: int | None, text: str) -> None:
    if not text or not text.strip():
        return
    db.add(Embedding(content_type=content_type, content_id=content_id, text=text, vector=embed_text(text)))


def _to_result(row: Embedding, score: float | None = None) -> dict:
    return {
        "content_type": row.content_type,
        "content_id": row.content_id,
        "text": row.text,
        "score": score,
    }


def search(db: Session, query: str, content_type: str | None = None, k: int = 5) -> list[dict]:
    """Semantic search over stored embeddings. Postgres uses pgvector's
    indexed cosine_distance() operator; SQLite (dev only) falls back to a
    brute-force cosine similarity scan in Python - fine for the row counts
    a dev/demo database has, not meant to scale."""
    query_vector = embed_text(query)

    base_query = db.query(Embedding)
    if content_type:
        base_query = base_query.filter(Embedding.content_type == content_type)

    dialect = db.get_bind().dialect.name

    if dialect == "postgresql":
        distance = Embedding.vector.cosine_distance(query_vector)
        rows = base_query.add_columns(distance.label("distance")).order_by(distance).limit(k).all()
        # cosine_distance is 1 - cosine_similarity; report similarity (higher
        # = more relevant) so both dialects' `score` mean the same thing.
        return [_to_result(row, score=1 - dist) for row, dist in rows]

    import numpy as np

    candidates = base_query.all()
    if not candidates:
        return []

    qv = np.array(query_vector)
    scored = []
    for row in candidates:
        v = np.array(row.vector)
        similarity = float(np.dot(qv, v) / (np.linalg.norm(qv) * np.linalg.norm(v) + 1e-9))
        scored.append((similarity, row))
    scored.sort(key=lambda pair: pair[0], reverse=True)

    return [_to_result(row, score=similarity) for similarity, row in scored[:k]]
