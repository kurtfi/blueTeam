import asyncio
import os
import sys
from pathlib import Path
from contextlib import AsyncExitStack

# Add src/Agentix and src/AgenticCommon to sys.path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir))
sys.path.insert(0, str(root_dir.parent / "AgenticCommon"))

from mcp import ClientSession
from mcp.client.sse import sse_client
from agentix.agents.factory import AgentFactory
from agentix.registry.catalog import ToolCatalog

# Explicitly routing environment variables to Ollama for testing.
os.environ["AGENTIX_LLM_PROVIDER"] = "ollama"
os.environ["OLLAMA_MODEL"] = os.getenv("OLLAMA_MODEL", "qwen3.5:9b")
os.environ["OLLAMA_BASE_URL"] = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
os.environ["AGENTIX_LOG_LEVEL"] = os.getenv("AGENTIX_LOG_LEVEL", "ERROR") # To reduce log verbosity

async def main():
    print("="*70)
    print(f"🚀 Initializing SOC Analyst with Ollama ({os.environ['OLLAMA_MODEL']})...")
    print("="*70)
    
    catalog = ToolCatalog()
    
    # Establish MCP (Tool Server) connection - use TriageCore port 8081 by default
    mcp_url = os.getenv("AGENTIX_SOC_MCP_URL", "http://localhost:8081/sse")
    print(f"🔌 Connecting to: MCP Tools Server ({mcp_url})...")
    try:
        stack = AsyncExitStack()
        stdio_transport = await stack.enter_async_context(sse_client(mcp_url))
        read_stream, write_stream = stdio_transport
        mcp_session = await stack.enter_async_context(ClientSession(read_stream, write_stream))
        await mcp_session.initialize()
        
        await catalog.register_mcp_client(mcp_session)
        print(f"✅ Tools successfully loaded! (Total {len(catalog.all_tools())} tools)")
    except Exception as e:
        print(f"❌ Failed to connect to MCP Server: {e}")
        print("Please make sure 'docker compose up soc-mcp' is running.")
        return

    # Load the agent
    agent = AgentFactory.create("soc_analyst", catalog=catalog)
    print(f"✅ Agent loaded. Model: {agent._llm.model}\n")
    
    prompt = "Received T1003.008 alert from Wazuh. agent_id=000, src_ip=10.10.10.99. Intervene immediately."
    print(f"👤 User: {prompt}\n")
    print("🤖 Agent Response Stream:\n")
    
    # Run the agent and listen for responses
    try:
        async for step in agent.run_stream(session_id="ollama-test-session", user_message=prompt):
            if step.step_type.name == "THINK":
                print(f"🧠 [THINK] {step.content}")
            elif step.step_type.name == "OBSERVE":
                # Truncating output to avoid long logs
                output = str(step.tool_output)[:150] + "..." if step.tool_output else "None"
                print(f"🔍 [OBSERVE] Tool '{step.tool_name}' result: {output}")
            elif step.step_type.name == "CONFIRM":
                print(f"\n⚠️ [APPROVAL REQUIRED] {step.content}")
                print("🛑 Agent stopped for a destructive command and is waiting for human approval. Test successful!\n")
                break
            elif step.step_type.name == "ANSWER":
                print(f"\n💬 [ANSWER]\n{step.content}\n")
    finally:
        # Clean up resources
        await stack.aclose()

if __name__ == "__main__":
    asyncio.run(main())
