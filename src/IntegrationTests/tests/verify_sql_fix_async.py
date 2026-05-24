import asyncio
import re
from unittest.mock import AsyncMock, MagicMock

# Mocking the dependency since we don't have a live LLM for this test
class MockLLMClient:
    def __init__(self, **kwargs):
        pass
    async def chat(self, messages, tools=None, tool_choice="auto"):
        # Simulate LLM translating a complex prompt
        return {"content": "SELECT * FROM users WHERE active = true"}

async def test_logic_async(query):
    print(f"Testing: '{query}'")
    clean_query = query.strip()
    
    # 1. Remove Markdown code blocks if present
    if clean_query.startswith("```"):
        clean_query = clean_query.split("\n", 1)[-1]
        if "```" in clean_query:
            clean_query = clean_query.rsplit("```", 1)[0]
        clean_query = clean_query.strip()

    # 2. Strip comments
    while clean_query.startswith("--") or clean_query.startswith("/*"):
        if clean_query.startswith("--"):
            clean_query = clean_query.split("\n", 1)[1].strip() if "\n" in clean_query else ""
        else:
            clean_query = clean_query.split("*/", 1)[1].strip() if "*/" in clean_query else ""

    # 3. Heuristic & Intelligence
    upper_query = clean_query.upper()
    if not (upper_query.startswith("SELECT") or upper_query.startswith("WITH")):
        # Phase 1: Regex
        match = re.match(r"^(?:LIST|SHOW)\s+(?:ALL\s+)?(?:FROM\s+)?(?:THE\s+)?([a-zA-Z0-9_]+)", upper_query)
        if match:
            table_name = match.group(1).lower()
            clean_query = f"SELECT * FROM {table_name}"
            upper_query = clean_query.upper()
            print(f"  Result: [Heuristic] Transformed to '{clean_query}'")
        else:
            # Phase 2: Mocked LLM
            print(f"  Result: [Intelligence] Falling back to LLM...")
            llm = MockLLMClient()
            response = await llm.chat([])
            clean_query = response["content"]
            upper_query = clean_query.upper()
            print(f"  Result: [Intelligence] Transformed to '{clean_query}'")
    else:
        print(f"  Result: [SQL] Valid SQL - '{clean_query}'")

    # 4. Security Check
    forbidden = ["INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE", "ALTER", "CREATE", "GRANT", "REVOKE"]
    for word in forbidden:
        if f" {word} " in f" {upper_query} ":
            print(f"  Result: SECURITY ERROR - Operation '{word}' is not allowed.")
            return
    
    print("  Result: CHECK PASSED")

async def main():
    await test_logic_async("SELECT * FROM users")
    await test_logic_async("List all users")
    await test_logic_async("Find active users in the system") # Complex NL for LLM
    await test_logic_async("DROP TABLE users") # Should fail SQL check in real life, here fails LLM result check if we mocked it differently

if __name__ == "__main__":
    asyncio.run(main())
