import asyncio
from agentix.tools.data.connectors import (
    MongoDBConnector,
    ElasticsearchConnector,
    RedisConnector,
    Neo4jConnector
)

async def verify_nosql():
    print("--- Verifying NoSQL Connectors Registration ---")
    
    tools = [
        MongoDBConnector(),
        ElasticsearchConnector(),
        RedisConnector(),
        Neo4jConnector()
    ]
    
    for tool in tools:
        print(f"Tool: {tool.name}")
        print(f"  Category: {tool.category}")
        print(f"  Description: {tool.description[:50]}...")
        # Check if parameters are correctly defined
        print(f"  Parameters: {list(tool.parameters['properties'].keys())}")
        print("-" * 30)

    print("\n--- Testing Read-Only Security in Neo4j ---")
    neo = Neo4jConnector()
    result = await neo.execute(query="CREATE (n:Person {name: 'Alice'})")
    print(f"Neo4j CREATE Blocked: {not result.success}")
    if not result.success:
        print(f"  Error: {result.error}")

    print("\n--- DONE ---")

if __name__ == "__main__":
    asyncio.run(verify_nosql())
