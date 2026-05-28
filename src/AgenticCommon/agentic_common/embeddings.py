"""
Embedding providers to generate vector representations of text.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

import structlog
from ollama import AsyncClient as OllamaAsyncClient
from openai import AsyncOpenAI

from agentic_common.settings import settings

logger = structlog.get_logger(__name__)


class BaseEmbeddingProvider(ABC):
    """Abstract base class for embedding models."""

    @abstractmethod
    async def embed_query(self, text: str) -> list[float]:
        """Embed a single query string."""
        pass

    @abstractmethod
    async def embed_documents(self, texts: list[str]) -> list[list[float]]:
        """Embed a batch of document strings."""
        pass


class OllamaEmbeddingProvider(BaseEmbeddingProvider):
    """Embeddings using Ollama."""

    def __init__(self, model: str | None = None) -> None:
        self.model = model or settings.ollama_embedding_model
        self.client = OllamaAsyncClient(host=settings.ollama_base_url)

    async def embed_query(self, text: str) -> list[float]:
        resp = await self.client.embeddings(model=self.model, prompt=text)
        emb = resp.embedding if hasattr(resp, "embedding") else resp["embedding"]
        return list(emb)

    async def embed_documents(self, texts: list[str]) -> list[list[float]]:
        embeddings: list[list[float]] = []
        for text in texts:
            emb = await self.embed_query(text)
            embeddings.append(emb)
        return embeddings


class OpenAIEmbeddingProvider(BaseEmbeddingProvider):
    """Embeddings using OpenAI."""

    def __init__(self, model: str = "text-embedding-3-small") -> None:
        self.model = model
        self.client = AsyncOpenAI(api_key=settings.openai_api_key)

    async def embed_query(self, text: str) -> list[float]:
        resp = await self.client.embeddings.create(input=[text], model=self.model)
        return resp.data[0].embedding

    async def embed_documents(self, texts: list[str]) -> list[list[float]]:
        resp = await self.client.embeddings.create(input=texts, model=self.model)
        return [item.embedding for item in resp.data]


class EmbeddingFactory:
    """Factory to create the configured embedding provider."""

    @staticmethod
    def create_provider(provider_name: str | None = None) -> BaseEmbeddingProvider:
        provider = provider_name or settings.agentix_embedding_provider

        if provider == "ollama":
            return OllamaEmbeddingProvider()
        elif provider == "openai":
            return OpenAIEmbeddingProvider()
        else:
            logger.warning("embeddings.factory.unknown_provider", provider=provider, fallback="ollama")
            return OllamaEmbeddingProvider()
