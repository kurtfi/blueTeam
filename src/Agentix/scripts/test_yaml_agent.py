import asyncio
import os
import structlog
from pathlib import Path

from agentix.agents.factory import AgentFactory
from agentix.registry.catalog import ToolCatalog
from agentic_common.base_tool import BaseTool, ToolResult

# Configure logging to see the ReAct loop
structlog.configure()

class MockTool(BaseTool):
    """A tool for testing filters."""
    def __init__(self, name: str, category: str):
        self.name = name
        self.category = category
        self.description = f"A special {category} tool for {name} operations."
    
    async def execute(self, **kwargs) -> ToolResult:
        return ToolResult(success=True, output="Mock result")

async def test_agent_loading():
    print("\n--- Testing YAML Agent Loading ---")
    
    # 0. Disable embeddings for pure keyword testing
    from agentic_common.settings import settings
    settings.agentix_embedding_provider = "none"
    
    # 1. Setup Catalog
    catalog = ToolCatalog()
    catalog.register(MockTool(name="research_tools", category="Data"))
    catalog.register(MockTool(name="file_manager", category="System"))
    
    print(f"Catalog has tools: {[t.name for t in catalog.all_tools()]}")

    # 2. Create Researcher Agent
    print("\n[Researcher Agent Test]")
    researcher = AgentFactory.create("researcher", catalog=catalog)
    researcher._config.tool_filters.names.append("research_tools")
    
    tools = await researcher._catalog.select(
        "Data operations", 
        category_filter=researcher._config.tool_filters.categories,
        name_filter=researcher._config.tool_filters.names
    )
    
    print(f"Researcher sees tools: {[t.name for t in tools]}")
    assert "research_tools" in [t.name for t in tools]
    assert "file_manager" not in [t.name for t in tools]
    
    # 3. Create SysAdmin Agent
    print("\n[SysAdmin Agent Test]")
    sysadmin = AgentFactory.create("sysadmin", catalog=catalog)
    sysadmin._config.tool_filters.names.append("file_manager")
    
    tools = await sysadmin._catalog.select(
        "System operations",
        category_filter=sysadmin._config.tool_filters.categories,
        name_filter=sysadmin._config.tool_filters.names
    )
    
    print(f"SysAdmin sees tools: {[t.name for t in tools]}")
    assert "file_manager" in [t.name for t in tools]
    assert "research_tools" not in [t.name for t in tools]

    print("\n--- All Loading Tests Passed! ---")

if __name__ == "__main__":
    asyncio.run(test_agent_loading())
