"""Standalone service that exposes embed_text()'s local model over HTTP,
so it can run in its own process holding nothing but the embedding model -
see embed_text()'s EMBEDDINGS_SERVICE_URL check in embeddings.py for why.

Run with: uvicorn app.embeddings_service:app
"""

from fastapi import FastAPI
from pydantic import BaseModel

from app.embeddings import _embed_local

app = FastAPI(title="SentraOps Embeddings Service")


class EmbedRequest(BaseModel):
    text: str


class EmbedResponse(BaseModel):
    vector: list[float]


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/embed", response_model=EmbedResponse)
def embed(payload: EmbedRequest) -> EmbedResponse:
    return EmbedResponse(vector=_embed_local(payload.text))
