import os
import time
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

        # On Render's free tier the embeddings service sleeps after 15min
        # idle, same as this one - confirmed by testing that a 30s timeout
        # isn't enough for its cold-start wake (~30-60s), which was turning
        # into a 500 here instead of just a slow-but-successful request.
        # Retries cover two cases: the cold-start timeout above, and 429/5xx
        # responses when the service is busy. A simulate run embeds every
        # event in a row, so a burst can hit a rate limit even though each
        # single request is fine. Waits grow 1s, 2s, 4s, 8s (or use the
        # server's Retry-After header if it sends one), then the error is raised.
        max_attempts = 5
        last_error: Exception | None = None
        for attempt in range(max_attempts):
            try:
                response = httpx.post(f"{service_url}/embed", json={"text": text}, timeout=90)
                response.raise_for_status()
                return response.json()["vector"]
            except httpx.HTTPStatusError as exc:
                last_error = exc
                retryable = exc.response.status_code == 429 or exc.response.status_code >= 500
                if not retryable:
                    raise
                retry_after = exc.response.headers.get("Retry-After", "")
                delay = float(retry_after) if retry_after.replace(".", "", 1).isdigit() else 2**attempt
            except httpx.HTTPError as exc:
                last_error = exc
                delay = 2**attempt
            if attempt < max_attempts - 1:
                time.sleep(delay)
        raise last_error
    return _embed_local(text)
