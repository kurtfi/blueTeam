import asyncio
import json
import logging
import sys
from pathlib import Path
from contextlib import AsyncExitStack

# Add workspace package paths to sys.path
root_dir = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(root_dir / "src/Agentix"))
sys.path.insert(0, str(root_dir / "src/AgenticCommon"))

from mcp import ClientSession
from mcp.client.sse import sse_client
from agentic_common.settings import settings
from agentix.agents.factory import AgentFactory
from agentix.registry.catalog import ToolCatalog
from agentic_common.memory.redis_store import RedisSessionStore

logging.basicConfig(level=logging.INFO, stream=sys.stdout,
                    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("verify_soc_agent_react")

async def run_debug():
    session_id = "test-soc-agent-session"
    logger.info("Initializing RedisSessionStore...")
    redis_store = RedisSessionStore(redis_url=settings.redis_url)
    
    logger.info("Clearing old session %s...", session_id)
    await redis_store.clear(session_id)
    await redis_store.set_metadata(session_id, "owner_id", "admin")

    catalog = ToolCatalog()
    
    async with AsyncExitStack() as stack:
        try:
            logger.info("Connecting to SOC MCP: %s...", settings.agentix_soc_mcp_url)
            soc_transport = await stack.enter_async_context(sse_client(settings.agentix_soc_mcp_url))
            soc_read, soc_write = soc_transport
            soc_session = await stack.enter_async_context(ClientSession(soc_read, soc_write))
            await soc_session.initialize()
            await catalog.register_mcp_client(soc_session)
            
            logger.info("SOC MCP tools synced. Total tools registered: %d", len(catalog.all_tools()))
        except Exception as e:
            logger.error("Failed to connect/sync SOC MCP tools: %s", e)
            await redis_store.close()
            return

        # Prepare alert details
        alert_payload = {
            'rule': {
                'id': '100002',
                'description': 'MITRE T1003.008 - OS Credential Dumping (/etc/shadow access)',
                'level': 10,
                'mitre': {
                    'id': ['T1003', 'T1003.008'],
                    'tactic': ['Credential Access'],
                    'technique': ['OS Credential Dumping']
                }
            },
            'agent': {
                'id': '000',
                'name': 'wazuh-manager',
                'ip': '127.0.0.1'
            },
            'data': {
                'srcip': '10.10.10.99',
                'srcuser': 'www-data',
                'command': 'cat /etc/shadow'
            }
        }
        
        prompt = f"Received T1003.008 alert from Wazuh for agent 000. Here are the alert details: {json.dumps(alert_payload)}. Which playbook should we run and what is the response plan? Find and trigger the playbook."
        
        logger.info("Initializing SOC Analyst agent...")
        orchestrator = AgentFactory.create(
            "soc_analyst",
            catalog=catalog,
            memory=redis_store
        )
        
        logger.info("Starting run_stream with Ollama (gemma4:e4b)...")
        print("\n" + "="*80)
        print("🤖 SOC Analyst ReAct Loop Stream")
        print("="*80)
        
        async for step in orchestrator.run_stream(session_id=session_id, user_message=prompt):
            if step.step_type.name == "THINK":
                print(f"\n🧠 [THINK] {step.content}")
            elif step.step_type.name == "OBSERVE":
                print(f"🔍 [OBSERVE] Tool '{step.tool_name}' result:\n{step.tool_output}")
            elif step.step_type.name == "CONFIRM":
                print(f"\n⚠️ [APPROVAL REQUIRED] {step.content}")
            elif step.step_type.name == "ANSWER":
                print(f"\n💬 [ANSWER]\n{step.content}\n")
        
        print("="*80 + "\n")

    await redis_store.close()
    logger.info("Done.")

if __name__ == "__main__":
    asyncio.run(run_debug())
