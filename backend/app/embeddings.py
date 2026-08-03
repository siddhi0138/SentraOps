from functools import lru_cache

MODEL_NAME = "all-MiniLM-L6-v2"


@lru_cache(maxsize=1)
def _get_model():
    # Imported lazily so importing this module doesn't force-load
    # sentence-transformers/torch for code paths that never embed anything
    # (and so the first real call, not module import, pays the load cost).
    from sentence_transformers import SentenceTransformer

    return SentenceTransformer(MODEL_NAME)


def embed_text(text: str) -> list[float]:
    """Free, local, no API key: runs entirely on this machine's CPU."""
    model = _get_model()
    return model.encode(text, normalize_embeddings=True).tolist()
