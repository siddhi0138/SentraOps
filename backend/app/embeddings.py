import os
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
    # overhead sitting in memory alongside it.
    return SentenceTransformer(MODEL_NAME, backend="onnx")


def _embed_local(text: str) -> list[float]:
    model = _get_model()
    return model.encode(text, normalize_embeddings=True).tolist()


def embed_text(text: str) -> list[float]:
    """Free, local, no API key by default - runs entirely on this process's
    own CPU. If EMBEDDINGS_SERVICE_URL is set, delegates to the standalone
    service in embeddings_service.py instead of loading the model here.

    That split exists for memory-constrained deployments (confirmed via
    testing against Render's 512MB free tier): the embedding model alone
    fits comfortably, but this process also holds LangGraph, the Neo4j
    driver, the Kubernetes client, and everything else main.py imports -
    together they don't fit. Splitting the model out to its own process,
    which holds nothing else, fits within the same limit that OOMs it here."""
    service_url = os.environ.get("EMBEDDINGS_SERVICE_URL")
    if service_url:
        import httpx

        response = httpx.post(f"{service_url}/embed", json={"text": text}, timeout=30)
        response.raise_for_status()
        return response.json()["vector"]
    return _embed_local(text)
