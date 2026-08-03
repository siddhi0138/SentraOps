from functools import lru_cache

MODEL_NAME = "all-MiniLM-L6-v2"


@lru_cache(maxsize=1)
def _get_model():
    # Imported lazily so importing this module doesn't force-load
    # sentence-transformers/torch for code paths that never embed anything
    # (and so the first real call, not module import, pays the load cost).
    from sentence_transformers import SentenceTransformer

    # backend="onnx" runs inference through ONNX Runtime instead of full
    # PyTorch - same model, same output, but without PyTorch's own runtime
    # overhead sitting in memory alongside it. Needed to fit this process
    # in a 512MB container (confirmed via testing: the plain PyTorch path
    # OOMs there the first time this function is actually called).
    return SentenceTransformer(MODEL_NAME, backend="onnx")


def embed_text(text: str) -> list[float]:
    """Free, local, no API key: runs entirely on this machine's CPU."""
    model = _get_model()
    return model.encode(text, normalize_embeddings=True).tolist()
