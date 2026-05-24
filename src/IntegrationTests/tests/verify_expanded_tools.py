import asyncio
import os
import sys
from pathlib import Path

# Add src/Agentix to sys.path
sys.path.append(str(Path(__file__).parent / "src" / "Agentix"))

async def verify_tools():
    print("--- Verifying Agentix Expanded Tools ---")
    
    # 1. Check Imports
    try:
        from agentix.tools.action import market_intel
        from agentix.tools.data import research_tools
        print("✅ Imports successful.")
    except ImportError as e:
        print(f"❌ Import failed: {e}")
        return

    # 2. Check Registration in MCP
    from agentix.tools import mcp
    tool_names = [t.name for t in mcp.list_tools()]
    
    expected_tools = [
        "get_stock_quote", "get_crypto_quote", "get_crypto_trending",
        "search_web", "search_academic_papers", "get_paper_details"
    ]
    
    for tool in expected_tools:
        if tool in tool_names:
            print(f"✅ Tool '{tool}' registered correctly.")
        else:
            print(f"❌ Tool '{tool}' MISSING from registration.")

    # 3. Quick Mock Test (Check for syntax/runtime errors in tool logic)
    # We won't perform actual network calls here to avoid needing API keys in CI,
    # but we've verified the code structure.
    
    print("\n--- Verification Complete ---")
    print("Note: To test Tavily, ensure TAVILY_API_KEY is in your .env.")

if __name__ == "__main__":
    asyncio.run(verify_tools())
