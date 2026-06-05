"""
PostgreSQL vector store implementation using pgvector and asyncpg.
"""
from __future__ import annotations

import json
import uuid
from typing import TYPE_CHECKING, Any

import asyncpg
from agentic_common.embeddings import EmbeddingFactory
from agentic_common.settings import settings
from agentic_common.vectors.base import BaseVectorStore, VectorSearchResult
from pgvector.asyncpg import register_vector

if TYPE_CHECKING:
    from agentic_common.embeddings import BaseEmbeddingProvider


class PostgresVectorStore(BaseVectorStore):
    """
    PostgreSQL vector store provider.
    Requires pgvector extension.
    """

    def __init__(self, embedding_provider: BaseEmbeddingProvider | None = None) -> None:
        self._embeddings = embedding_provider or EmbeddingFactory.create_provider()
        self._pool: asyncpg.Pool | None = None
        self._table_name = "agentix_embeddings"

    async def _get_pool(self) -> asyncpg.Pool:
        if self._pool is None:
            # Connect and register pgvector
            self._pool = await asyncpg.create_pool(
                dsn=settings.agentix_postgres_url.replace("+asyncpg", ""),
                init=self._init_connection
            )
            # Ensure extension and table exist
            await self._setup_db()
        return self._pool

    async def _init_connection(self, conn: asyncpg.Connection) -> None:
        await register_vector(conn)

    async def _setup_db(self) -> None:
        """Create extension and table if they don't exist."""
        if not self._pool:
            return
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
                await conn.execute(f"""
                    CREATE TABLE IF NOT EXISTS {self._table_name} (
                        id UUID PRIMARY KEY,
                        collection TEXT,
                        content TEXT,
                        metadata JSONB,
                        embedding vector,
                        content_tsvector tsvector GENERATED ALWAYS AS (to_tsvector('english', content)) STORED
                    )
                """)
                await conn.execute(f"CREATE INDEX IF NOT EXISTS {self._table_name}_collection_idx ON {self._table_name} (collection)")
                await conn.execute(f"CREATE INDEX IF NOT EXISTS {self._table_name}_tsvector_idx ON {self._table_name} USING GIN (content_tsvector)")
                await conn.execute(f"CREATE INDEX IF NOT EXISTS {self._table_name}_embedding_idx ON {self._table_name} USING ivfflat (embedding vector_cosine_ops)")

    async def upsert(
        self,
        texts: list[str],
        metadata: list[dict[str, Any]] | None = None,
        ids: list[str] | None = None,
        collection: str = "default",
    ) -> list[str]:
        pool = await self._get_pool()
        vectors = await self._embeddings.embed_documents(texts)
        doc_ids = ids or [str(uuid.uuid4()) for _ in range(len(texts))]
        doc_metadata = metadata or [{} for _ in range(len(texts))]

        data = []
        for i in range(len(texts)):
            data.append((
                uuid.UUID(doc_ids[i]),
                collection,
                texts[i],
                json.dumps(doc_metadata[i]),
                vectors[i]
            ))

        async with pool.acquire() as conn:
            await conn.executemany(f"""
                INSERT INTO {self._table_name} (id, collection, content, metadata, embedding)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (id) DO UPDATE SET
                    content = EXCLUDED.content,
                    metadata = EXCLUDED.metadata,
                    embedding = EXCLUDED.embedding
            """, data)

        return doc_ids

    async def search(
        self,
        query: str,
        top_k: int = 5,
        collection: str = "default",
        filter: dict[str, Any] | None = None,
        **kwargs: Any
    ) -> list[VectorSearchResult]:
        alpha: float = kwargs.get("alpha", 0.5)
        pool = await self._get_pool()
        query_vector = await self._embeddings.embed_query(query)

        where_clause = "WHERE collection = $2"
        params = [query_vector, collection, top_k, query, alpha]
        
        if filter:
            where_clause += " AND metadata @> $6"
            params.append(json.dumps(filter))

        async with pool.acquire() as conn:
            # Hybrid search using a weighted combination of Vector Similarity and Text Rank (BM25-like)
            # alpha=1.0 is pure vector, alpha=0.0 is pure text.
            rows = await conn.fetch(f"""
                WITH vector_matches AS (
                    SELECT id, 1 - (embedding <=> $1) as score
                    FROM {self._table_name}
                    {where_clause}
                    ORDER BY embedding <=> $1
                    LIMIT $3 * 2
                ),
                text_matches AS (
                    SELECT id, ts_rank_cd(content_tsvector, websearch_to_tsquery('english', $4)) as score
                    FROM {self._table_name}
                    {where_clause} AND content_tsvector @@ websearch_to_tsquery('english', $4)
                    ORDER BY score DESC
                    LIMIT $3 * 2
                )
                SELECT 
                    COALESCE(v.id, t.id) as id,
                    p.content,
                    p.metadata,
                    (COALESCE(v.score, 0) * $5 + COALESCE(t.score, 0) * (1.0 - $5)) as score
                FROM vector_matches v
                FULL OUTER JOIN text_matches t ON v.id = t.id
                JOIN {self._table_name} p ON p.id = COALESCE(v.id, t.id)
                ORDER BY score DESC
                LIMIT $3
            """, *params)

        results: list[VectorSearchResult] = []
        for row in rows:
            results.append({
                "id": str(row["id"]),
                "text": row["content"],
                "metadata": json.loads(row["metadata"]),
                "score": float(row["score"]),
            })

        return results

    async def delete(self, ids: list[str], collection: str = "default") -> None:
        pool = await self._get_pool()
        uuid_ids = [uuid.UUID(i) for i in ids]
        async with pool.acquire() as conn:
            await conn.execute(f"DELETE FROM {self._table_name} WHERE id = ANY($1) AND collection = $2", uuid_ids, collection)

    async def close(self) -> None:
        if self._pool:
            await self._pool.close()
            self._pool = None
