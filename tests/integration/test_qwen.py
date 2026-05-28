import pytest
import os
import json
from contextlib import AsyncExitStack

from mcp import ClientSession
from mcp.client.sse import sse_client

from agentic_common.settings import settings
from agentix.registry.catalog import ToolCatalog
from agentix.agents.loader import AgentLoader
from ollama import AsyncClient

pytestmark = pytest.mark.skipif(
    not os.getenv("OLLAMA_BASE_URL"), 
    reason="OLLAMA_BASE_URL is not configured"
)

@pytest.mark.asyncio
async def test_qwen_soc_analyst_flow():
    catalog = ToolCatalog()
    
    # We will try to connect to MCP, but if it fails we might just skip the MCP part
    # For integration test, we expect MCP to be up or we skip the full test.
    async with AsyncExitStack() as stack:
        try:
            gen_transport = await stack.enter_async_context(sse_client(settings.agentix_general_mcp_url))
            gen_read, gen_write = gen_transport
            gen_session = await stack.enter_async_context(ClientSession(gen_read, gen_write))
            await gen_session.initialize()
            await catalog.register_mcp_client(gen_session)
            
            soc_transport = await stack.enter_async_context(sse_client(settings.agentix_triage_core_url))
            soc_read, soc_write = soc_transport
            soc_session = await stack.enter_async_context(ClientSession(soc_read, soc_write))
            await soc_session.initialize()
            await catalog.register_mcp_client(soc_session)
        except Exception as e:
            pytest.skip(f"Skipping test due to MCP connection failure: {e}")

        config = AgentLoader.load_by_name("soc_analyst")
        system_prompt = config.system_prompt_override
        
        matched_tools = await catalog.select(
            "T1003.008 alert",
            category_filter=config.tool_filters.categories,
            name_filter=config.tool_filters.names
        )
        tool_schemas = [t.to_openai_schema() for t in matched_tools]

        alert_payload = {
            'rule': {
                'id': '100002',
                'description': 'MITRE T1003.008',
            },
            'agent': {'id': '000'}
        }
        
        user_prompt = f"Analyze: {json.dumps(alert_payload)}"
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]

        client = AsyncClient(host=settings.ollama_base_url)

        kwargs = {
            "model": "gemma4:e4b",
            "messages": messages,
            "options": {"temperature": 0.1, "num_predict": 4096},
            "tools": tool_schemas
        }
        
        response1 = await client.chat(**kwargs)
        message = response1.get("message", {})
        tool_calls = message.get("tool_calls") or []
        
        assert message.get("role") == "assistant"
        
        if tool_calls:
            formatted_tool_calls = []
            for tc in tool_calls:
                formatted_tool_calls.append({
                    "id": tc.get("id", "call_12345"),
                    "type": "function",
                    "function": tc.get("function", {})
                })
            
            messages.append({
                "role": "assistant",
                "content": message.get("content", ""),
                "tool_calls": formatted_tool_calls
            })
            
            messages.append({
                "role": "tool",
                "tool_call_id": formatted_tool_calls[0]["id"],
                "content": "Playbook PB-001 found"
            })

            formatted_messages = []
            for m in messages:
                m_copy = dict(m)
                if m_copy.get("role") == "assistant" and m_copy.get("tool_calls"):
                    formatted_tcs = []
                    for tc in m_copy["tool_calls"]:
                        tc_copy = dict(tc)
                        if "function" in tc_copy and "arguments" in tc_copy["function"]:
                            func_copy = dict(tc_copy["function"])
                            args = func_copy.get("arguments")
                            if isinstance(args, str):
                                try:
                                    func_copy["arguments"] = json.loads(args)
                                except Exception:
                                    pass
                            tc_copy["function"] = func_copy
                        formatted_tcs.append(tc_copy)
                    m_copy["tool_calls"] = formatted_tcs
                formatted_messages.append(m_copy)

            kwargs["messages"] = formatted_messages
            response2 = await client.chat(**kwargs)
            msg2 = response2.get("message", {})
            assert msg2.get("role") == "assistant"
