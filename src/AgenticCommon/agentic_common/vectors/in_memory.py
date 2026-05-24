"""
Simple in-memory vector store using cosine similarity.
"""
from __future__ import annotations

import math
import uuid
from typing import TYPE_CHECKING, Any

from agentic_common.embeddings import EmbeddingFactory
from agentic_common.vectors.base import BaseVectorStore, VectorSearchResult

if TYPE_CHECKING:
    from agentic_common.embeddings import BaseEmbeddingProvider


class InMemoryVectorStore(BaseVectorStore):
    """
    A simple in-memory vector store.
    Useful for testing, demos, or very small datasets.
    """

    def __init__(self, embedding_provider: BaseEmbeddingProvider | None = None) -> None:
        self._embeddings = embedding_provider or EmbeddingFactory.create_provider()
        self._collections: dict[str, list[dict[str, Any]]] = {}

    async def upsert(
        self,
        texts: list[str],
        metadata: list[dict[str, Any]] | None = None,
        ids: list[str] | None = None,
        collection: str = "default",
    ) -> list[str]:
        if collection not in self._collections:
            self._collections[collection] = []

        vectors = await self._embeddings.embed_documents(texts)
        new_ids = ids or [str(uuid.uuid4()) for _ in range(len(texts))]
        new_metadata = metadata or [{} for _ in range(len(texts))]

        for i, text in enumerate(texts):
            doc = {
                "id": new_ids[i],
                "text": text,
                "vector": vectors[i],
                "metadata": new_metadata[i],
            }
            # Simple replace if ID exists
            existing_idx = next((idx for idx, d in enumerate(self._collections[collection]) if d["id"] == doc["id"]), -1)
            if existing_idx != -1:
                self._collections[collection][existing_idx] = doc
            else:
                self._collections[collection].append(doc)

        return new_ids

    async def search(
        self,
        query: str,
        top_k: int = 5,
        collection: str = "default",
        alpha: float = 0.5,
        filter: dict | None = None,
    ) -> list[VectorSearchResult]:
        if collection not in self._collections or not self._collections[collection]:
            return []

        # 0. Apply Filter
        docs = self._collections[collection]
        if filter:
            filtered_docs = []
            for doc in docs:
                match = True
                for k, v in filter.items():
                    if doc["metadata"].get(k) != v:
                        match = False
                        break
                if match:
                    filtered_docs.append(doc)
            docs = filtered_docs

        if not docs:
            return []

        # 1. Semantic Search
        query_vector = await self._embeddings.embed_query(query)
        semantic_scored: list[tuple[str, float]] = []
        for doc in docs:
            score = self._cosine_similarity(query_vector, doc["vector"])
            semantic_scored.append((doc["id"], score))
        
        semantic_scored.sort(key=lambda x: x[1], reverse=True)
        semantic_rank = {doc_id: i + 1 for i, (doc_id, _) in enumerate(semantic_scored)}

        # 2. Keyword Search (Simple)
        query_words = set(query.lower().split())
        keyword_scored: list[tuple[str, float]] = []
        for doc in docs:
            doc_words = set(doc["text"].lower().split())
            intersection = query_words.intersection(doc_words)
            keyword_scored.append((doc["id"], len(intersection) / max(len(query_words), 1)))
        
        keyword_scored.sort(key=lambda x: x[1], reverse=True)
        keyword_rank = {doc_id: i + 1 for i, (doc_id, _) in enumerate(keyword_scored)}

        # 3. Reciprocal Rank Fusion (RRF)
        # score = sum( 1 / (k + rank(d)) )
        k = 60
        fused_scores: dict[str, float] = {}
        all_ids = set(semantic_rank.keys()) | set(keyword_rank.keys())
        
        for doc_id in all_ids:
            s_rank = semantic_rank.get(doc_id, 1000)
            k_rank = keyword_rank.get(doc_id, 1000)
            
            # alpha=1 -> pure semantic, alpha=0 -> pure keyword
            score = (alpha * (1.0 / (k + s_rank))) + ((1.0 - alpha) * (1.0 / (k + k_rank)))
            fused_scores[doc_id] = score

        # 4. Final aggregation
        id_to_doc = {d["id"]: d for d in docs}
        sorted_ids = sorted(fused_scores.keys(), key=lambda x: fused_scores[x], reverse=True)

        results: list[VectorSearchResult] = []
        for doc_id in sorted_ids[:top_k]:
            doc = id_to_doc[doc_id]
            results.append({
                "id": doc["id"],
                "text": doc["text"],
                "metadata": doc["metadata"],
                "score": fused_scores[doc_id],
            })

        return results

    async def delete(self, ids: list[str], collection: str = "default") -> None:
        if collection not in self._collections:
            return
        self._collections[collection] = [d for d in self._collections[collection] if d["id"] not in ids]

    def _cosine_similarity(self, v1: list[float], v2: list[float]) -> float:
        """Compute cosine similarity between two vectors."""
        dot_product = sum(a * b for a, b in zip(v1, v2))
        magnitude1 = math.sqrt(sum(a * a for a in v1))
        magnitude2 = math.sqrt(sum(b * b for b in v2))
        if magnitude1 == 0 or magnitude2 == 0:
            return 0.0
        return dot_product / (magnitude1 * magnitude2)
