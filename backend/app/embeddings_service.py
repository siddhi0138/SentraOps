"""Standalone service that exposes embed_text()'s local model over HTTP,
so it can run in its own process holding nothing but the embedding model -
see embed_text()'s EMBEDDINGS_SERVICE_URL check in embeddings.py for why.

Run with: uvicorn app.embeddings_service:app
"""

from fastapi import FastAPI
from pydantic import BaseModel

from app.embeddings import _embed_local, _embed_local_batch

app = FastAPI(title="SentraOps Embeddings Service")


class EmbedRequest(BaseModel):
    text: str


class EmbedResponse(BaseModel):
    vector: list[float]


class EmbedBatchRequest(BaseModel):
    texts: list[str]


class EmbedBatchResponse(BaseModel):
    vectors: list[list[float]]


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/embed", response_model=EmbedResponse)
def embed(payload: EmbedRequest) -> EmbedResponse:
    return EmbedResponse(vector=_embed_local(payload.text))


@app.post("/embed_batch", response_model=EmbedBatchResponse)
def embed_batch(payload: EmbedBatchRequest) -> EmbedBatchResponse:
    if not payload.texts:
        return EmbedBatchResponse(vectors=[])
    return EmbedBatchResponse(vectors=_embed_local_batch(payload.texts))
