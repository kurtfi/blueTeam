"""
Abstract base class for vector store providers.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, TypedDict


class VectorSearchResult(TypedDict):
    """Result of a semantic search."""
    id: str
    text: str
    metadata: dict[str, Any]
    score: float

class BaseVectorStore(ABC):
    """Abstract base class for vector storage and retrieval."""

    @abstractmethod
    async def upsert(
        self, 
        texts: list[str], 
        metadata: list[dict[str, Any]] | None = None, 
        ids: list[str] | None = None
    ) -> list[str]:
        """Insert or update documents in the vector store."""
        pass

    @abstractmethod
    async def search(
        self, 
        query: str, 
        top_k: int = 5, 
        collection: str = "default",
        filter: dict[str, Any] | None = None,
        **kwargs: Any
    ) -> list[VectorSearchResult]:
        """Search for similar documents given a query."""
        pass

    @abstractmethod
    async def delete(self, ids: list[str], collection: str = "default") -> None:
        """Delete documents by their IDs."""
        pass
