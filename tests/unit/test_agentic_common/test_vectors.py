import asyncio
from unittest.mock import AsyncMock, MagicMock
import pytest
from agentic_common.vectors.in_memory import InMemoryVectorStore
from agentic_common.vectors.postgres import PostgresVectorStore


@pytest.mark.asyncio
async def test_in_memory_vector_store_basic():
    # Mock embeddings
    mock_embeddings = AsyncMock()
    mock_embeddings.embed_documents.return_value = [[0.1, 0.2], [0.3, 0.4]]
    mock_embeddings.embed_query.return_value = [0.15, 0.25]
    
    store = InMemoryVectorStore(embedding_provider=mock_embeddings)
    
    # Upsert
    ids = await store.upsert(
        texts=["hello world", "goodnight moon"],
        metadata=[{"source": "test1"}, {"source": "test2"}],
        collection="test_col"
    )
    
    assert len(ids) == 2
    mock_embeddings.embed_documents.assert_called_once_with(["hello world", "goodnight moon"])
    
    # Search
    results = await store.search(query="hello", collection="test_col")
    assert len(results) > 0
    assert results[0]["text"] in ("hello world", "goodnight moon")
    
    # Delete
    await store.delete(ids=[ids[0]], collection="test_col")
    results_after_delete = await store.search(query="hello", collection="test_col")
    # Verify first doc is deleted
    assert ids[0] not in [r["id"] for r in results_after_delete]


@pytest.mark.asyncio
async def test_in_memory_concurrency_lock():
    mock_embeddings = AsyncMock()
    
    active_calls = []
    max_concurrent_calls = [0]
    
    async def mock_embed(texts):
        active_calls.append(texts)
        max_concurrent_calls[0] = max(max_concurrent_calls[0], len(active_calls))
        await asyncio.sleep(0.02)
        active_calls.remove(texts)
        return [[0.1, 0.2] for _ in texts]
        
    mock_embeddings.embed_documents.side_effect = mock_embed
    
    store = InMemoryVectorStore(embedding_provider=mock_embeddings)
    
    # Run two upserts concurrently. Because they are wrapped in `async with self._lock`,
    # the second one will wait for the first one to complete, keeping concurrent calls at max 1.
    await asyncio.gather(
        store.upsert(texts=["text1"], collection="col1"),
        store.upsert(texts=["text2"], collection="col1")
    )
    
    assert max_concurrent_calls[0] == 1


def create_mock_pool(conn_mock):
    pool_mock = MagicMock()
    async_ctx = MagicMock()
    async_ctx.__aenter__ = AsyncMock(return_value=conn_mock)
    async_ctx.__aexit__ = AsyncMock(return_value=None)
    pool_mock.acquire.return_value = async_ctx
    return pool_mock


@pytest.mark.asyncio
async def test_postgres_vector_store_setup():
    mock_conn = AsyncMock()
    
    # Mock transaction async context manager
    mock_tx = MagicMock()
    mock_tx.__aenter__ = AsyncMock()
    mock_tx.__aexit__ = AsyncMock()
    mock_conn.transaction = MagicMock(return_value=mock_tx)
    
    mock_pool = create_mock_pool(mock_conn)
    
    store = PostgresVectorStore()
    store._pool = mock_pool
    
    await store._setup_db()
    
    # Verify index creation statement includes USING hnsw
    calls = [call[0][0] for call in mock_conn.execute.call_args_list]
    hnsw_index_call = next((c for c in calls if "USING hnsw" in c), None)
    assert hnsw_index_call is not None
