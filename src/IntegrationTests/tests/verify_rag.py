
import asyncio
import sys
import os

# Add src to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../agentix")))
# Actually, the package name is agentix and it's in src/Agentix/agentix
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agentic_common.vectors.in_memory import InMemoryVectorStore
from agentic_common.embeddings import BaseEmbeddingProvider
from general_mcp.tools.data.document_processor import search_document_catalog

class MockEmbeddingProvider(BaseEmbeddingProvider):
    async def embed_query(self, text: str) -> list[float]:
        # Simple mock: vector where each element is unique-ish
        return [float(ord(c)) for c in text[:8].ljust(8, ' ')]

    async def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [await self.embed_query(t) for t in texts]

async def test_vector_store():
    print("Testing InMemoryVectorStore...")
    mock_embeddings = MockEmbeddingProvider()
    store = InMemoryVectorStore(embedding_provider=mock_embeddings)
    
    texts = ["Apple is a fruit", "London is a city", "Python is a language"]
    await store.upsert(texts=texts)
    
    results = await store.search(query="Apple", top_k=3)
    assert len(results) == 3
    # Check descending order
    assert results[0]['score'] >= results[1]['score'] >= results[2]['score']
    print("Vector search results are sorted correctly.")

async def test_rag_tool():
    print("\nTesting RAGSearch Tool...")
    # This might fail if Ollama/Postgres is not running, so we'll catch it
    try:
        result = await search_document_catalog(query="test")
        print(f"Tool Result: {result}")
    except Exception as e:
        print(f"Tool crashed as expected: {e}")

async def test_postgres_vector_store():
    print("\nTesting PostgresVectorStore...")
    from agentic_common.vectors.postgres import PostgresVectorStore
    try:
        mock_embeddings = MockEmbeddingProvider()
        store = PostgresVectorStore(embedding_provider=mock_embeddings)
        
        texts = ["Berlin is the capital of Germany", "Paris is the capital of France"]
        await store.upsert(texts=texts, collection="test_col")
        
        results = await store.search(query="Germany", top_k=1, collection="test_col")
        print(f"Results for 'Germany': {results[0]['text']} (Score: {results[0]['score']:.4f})")
        assert "Berlin" in results[0]['text']
        await store.close()
        print("PostgresVectorStore search works!")
    except Exception as e:
        print(f"Postgres test skipped or failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_vector_store())
    # To test postgres, ensure docker is up and PGVECTOR is installed
    # asyncio.run(test_postgres_vector_store())
