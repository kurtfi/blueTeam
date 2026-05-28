import asyncio
import os
import sys
from pathlib import Path

# Add src/Agentix and src/AgenticCommon to sys.path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir))
sys.path.insert(0, str(root_dir.parent / "AgenticCommon"))

from agentix.agents.factory import AgentFactory
from agentix.registry.catalog import ToolCatalog
from agentic_common.base_tool import BaseTool, ToolResult
from typing import Any

import structlog
try:
    structlog.configure() # type: ignore
except Exception:
    pass

class MockTool(BaseTool):
    """A tool for testing filters."""
    def __init__(self, name: str, category: str):
        self.name = name
        self.category = category
        self.description = f"A special {category} tool for {name} operations."
    
    async def execute(self, context: dict[str, Any] | None = None, **kwargs: Any) -> ToolResult:
        return ToolResult(success=True, output="Mock result")

async def test_agent_loading():
    print("\n--- Testing YAML Agent Loading ---")
    
    # 0. Disable embeddings for pure keyword testing
    from agentic_common.settings import settings
    settings.agentix_embedding_provider = "none"
    
    # 1. Setup Catalog
    catalog = ToolCatalog()
    catalog.register(MockTool(name="query_siem_logs", category="Security"))
    catalog.register(MockTool(name="some_general_tool", category="General"))
    
    print(f"Catalog has tools: {[t.name for t in catalog.all_tools()]}")

    # 2. Create SOC Analyst Agent
    print("\n[SOC Analyst Agent Test]")
    soc_analyst = AgentFactory.create("soc_analyst", catalog=catalog)
    
    tools = await soc_analyst._catalog.select(
        "SIEM query", 
        category_filter=soc_analyst._config.tool_filters.categories,
        name_filter=soc_analyst._config.tool_filters.names
    )
    
    print(f"SOC Analyst sees tools: {[t.name for t in tools]}")
    assert "query_siem_logs" in [t.name for t in tools]
    assert "some_general_tool" not in [t.name for t in tools]
    
    print("\n--- All Loading Tests Passed! ---")

if __name__ == "__main__":
    asyncio.run(test_agent_loading())
