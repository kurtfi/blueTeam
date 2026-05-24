import asyncio
import os
import structlog
from pathlib import Path

from agentix.agents.factory import AgentFactory
from agentix.registry.catalog import ToolCatalog
from agentic_common.base_tool import BaseTool, ToolResult

structlog.configure()

class MockTool(BaseTool):
    """A tool for testing filters."""
    def __init__(self, name: str, category: str):
        self.name = name
        self.category = category
        self.description = f"A special {category} tool for {name} operations."
    
    async def execute(self, **kwargs) -> ToolResult:
        return ToolResult(success=True, output="Mock result")

async def test_crypto_agent():
    print("\n--- Testing Crypto Analyst Agent Loading ---")
    
    # 0. Disable embeddings for pure keyword testing
    from agentic_common.settings import settings
    settings.agentix_embedding_provider = "none"
    
    # 1. Setup Catalog
    catalog = ToolCatalog()
    catalog.register(MockTool(name="get_crypto_quote", category="Action"))
    catalog.register(MockTool(name="get_crypto_trending", category="Action"))
    catalog.register(MockTool(name="send_email", category="Action"))
    catalog.register(MockTool(name="irrelevant_data_tool", category="Data"))
    
    print(f"Catalog has tools: {[t.name for t in catalog.all_tools()]}")

    # 2. Create Crypto Agent
    print("\n[Crypto Analyst Agent Test]")
    crypto_agent = AgentFactory.create("crypto_analyst", catalog=catalog)
    
    # We test with a query that would normally match "data" as well
    # "Data operations"
    tools = await crypto_agent._catalog.select(
        "Action operations", 
        category_filter=crypto_agent._config.tool_filters.categories,
        name_filter=crypto_agent._config.tool_filters.names
    )
    
    selected_names = [t.name for t in tools]
    print(f"Crypto Analyst sees tools: {selected_names}")
    
    assert "get_crypto_quote" in selected_names
    assert "get_crypto_trending" in selected_names
    assert "send_email" in selected_names
    assert "irrelevant_data_tool" not in selected_names

    print("\n--- Crypto Analyst Tests Passed! ---")

if __name__ == "__main__":
    asyncio.run(test_crypto_agent())
