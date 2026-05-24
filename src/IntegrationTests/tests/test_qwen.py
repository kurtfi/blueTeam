import asyncio
import json
import logging
import sys
from contextlib import AsyncExitStack

from mcp import ClientSession
from mcp.client.sse import sse_client

from agentic_common.settings import settings
from agentix.registry.catalog import ToolCatalog
from agentix.agents.loader import AgentLoader

logging.basicConfig(level=logging.INFO, stream=sys.stdout)
logger = logging.getLogger("test_qwen")

async def main():
    catalog = ToolCatalog()
    
    async with AsyncExitStack() as stack:
        try:
            # 1. Connect to General MCP
            gen_transport = await stack.enter_async_context(sse_client(settings.agentix_general_mcp_url))
            gen_read, gen_write = gen_transport
            gen_session = await stack.enter_async_context(ClientSession(gen_read, gen_write))
            await gen_session.initialize()
            await catalog.register_mcp_client(gen_session)
            logger.info("Connected to General MCP: %s", settings.agentix_general_mcp_url)
            
            # 2. Connect to SOC MCP
            soc_transport = await stack.enter_async_context(sse_client(settings.agentix_soc_mcp_url))
            soc_read, soc_write = soc_transport
            soc_session = await stack.enter_async_context(ClientSession(soc_read, soc_write))
            await soc_session.initialize()
            await catalog.register_mcp_client(soc_session)
            logger.info("Connected to SOC MCP: %s", settings.agentix_soc_mcp_url)
        except Exception as e:
            logger.error("Failed to connect/sync MCP tools: %s", e)
            return

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
                'description': 'MITRE T1003.008 - OS Credential Dumping (/etc/shadow access)',
                'level': 10,
                'groups': ['mitre_t1003', 'credential_dumping'],
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
            },
            'full_log': 'May 22 16:35:21 wazuh-manager syslog: MITRE-ATTACK-SIM: T1003.008 user=www-data pid=31337 cmd=cat-etc-shadow file=/etc/shadow action=READ severity=CRITICAL src_ip=10.10.10.99',
            'timestamp': '2026-05-22T16:48:00Z',
            'location': '/var/log/attack_simulation.log'
        }
        
        alert_details = json.dumps(alert_payload, indent=2)
        user_prompt = f"""
Sen otonom bir Tier 1 (T1) SOC Analistisin. SIEM'den aşağıdaki alarm düştü:

ALARM DETAYLARI:
{alert_details}

GÖREVİN:
Bu alarmı analiz et, gerekli bağlamı topla, False Positive (FP) / True Positive (TP) ayrımını yap ve gerekirse olayı sınırlandırıp (containment) vaka oluştur. Aşağıdaki standart iş akışlarına (workflows) göre hareket etmelisin:

1. OS OS CREDENTIAL DUMPING AKIŞI (T1003):
   - /etc/shadow veya kimlik bilgisi erişimi varsa `find_playbook_for_alert` ile uygun playbook'u bul.
   - `trigger_playbook` ile playbook'u çalıştır ve adımlarını takip et.

Tüm adımlarını sırasıyla planla, uygun MCP araçlarını kullan ve nihai kararla birlikte eylemlerini özetle.
"""

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]

        from ollama import AsyncClient
        client = AsyncClient(host=settings.ollama_base_url)

        print("\n=== TURN 1 REQUEST (QWEN) ===")
        kwargs = {
            "model": "qwen3.5:9b",
            "messages": messages,
            "options": {"temperature": 0.1, "num_predict": 4096},
            "tools": tool_schemas
        }
        
        response1 = await client.chat(**kwargs)
        print("\n=== TURN 1 RAW OLLAMA RESPONSE ===")
        print(json.dumps(dict(response1), indent=2, default=str))

        message = response1.get("message", {})
        tool_calls = message.get("tool_calls") or []
        
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
            
            observation = """Uygun playbook'lar (1 adet bulundu):

  → **PB-001**: OS Credential Dumping – /etc/shadow Access [HIGH] MITRE: T1003, T1003.008

Playbook'u tetiklemek için: trigger_playbook(playbook_id='PB-001', ...)"""
            
            messages.append({
                "role": "tool",
                "tool_call_id": formatted_tool_calls[0]["id"],
                "content": observation
            })

            print("\n=== TURN 2 REQUEST (QWEN) ===")
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
            print("\n=== TURN 2 RAW OLLAMA RESPONSE ===")
            print(json.dumps(dict(response2), indent=2, default=str))
        else:
            print("\nNo tool calls in Turn 1!")

if __name__ == "__main__":
    asyncio.run(main())
