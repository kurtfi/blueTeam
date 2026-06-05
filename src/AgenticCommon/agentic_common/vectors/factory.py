"""
Factory to instantiate the appropriate vector store provider.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

import structlog
from agentic_common.settings import settings
from agentic_common.vectors.in_memory import InMemoryVectorStore
from agentic_common.vectors.postgres import PostgresVectorStore

if TYPE_CHECKING:
    from agentic_common.vectors.base import BaseVectorStore

logger = structlog.get_logger(__name__)


class VectorStoreFactory:
    """Factory to create the configured vector store provider."""

    @staticmethod
    def create_provider(provider_name: str | None = None) -> BaseVectorStore:
        provider = provider_name or getattr(settings, "agentix_vector_store", "inmemory")

        if provider == "inmemory":
            return InMemoryVectorStore()
        elif provider == "postgres":
            return PostgresVectorStore()
        else:
            logger.warning("vectors.factory.unknown_provider", provider=provider, fallback="inmemory")
            return InMemoryVectorStore()

# Global instance for singleton-like usage if needed
vector_store = VectorStoreFactory.create_provider()
