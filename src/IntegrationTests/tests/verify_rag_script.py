import asyncio
from agentic_common.vectors.in_memory import InMemoryVectorStore
from agentic_common.embeddings import EmbeddingFactory

async def test_filtering():
    print("Testing InMemoryVectorStore Filtering...")
    store = InMemoryVectorStore()
    
    texts = ["I love pizza", "I love pasta", "I love sushi"]
    metadata = [
        {"user_id": "user_1", "tag": "food"},
        {"user_id": "user_1", "tag": "food"},
        {"user_id": "user_2", "tag": "food"},
    ]
    
    await store.upsert(texts, metadata=metadata)
    
    print("\nSearching for 'food' as user_1...")
    res1 = await store.search("food", filter={"user_id": "user_1"})
    for r in res1:
        print(f" - Found: {r['text']} (User: {r['metadata']['user_id']})")
        assert r['metadata']['user_id'] == "user_1"
    
    print("\nSearching for 'food' as user_2...")
    res2 = await store.search("food", filter={"user_id": "user_2"})
    for r in res2:
        print(f" - Found: {r['text']} (User: {r['metadata']['user_id']})")
        assert r['metadata']['user_id'] == "user_2"
    
    print("\nFiltering test passed!")

if __name__ == "__main__":
    asyncio.run(test_filtering())
