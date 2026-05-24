import asyncio
import json
import logging
import sys
from contextlib import AsyncExitStack

from mcp import ClientSession
from mcp.client.sse import sse_client

from agentic_common.settings import settings
from agentix.agents.factory import AgentFactory
from agentix.registry.catalog import ToolCatalog
from agentic_common.memory.redis_store import RedisSessionStore
from agentix.core.llm import LLMClient

logging.basicConfig(level=logging.INFO, stream=sys.stdout,
                    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("debug_react_loop_raw")

async def run_debug():
    session_id = "debug-raw-react-loop"
    redis_store = RedisSessionStore(redis_url=settings.redis_url)
    await redis_store.clear(session_id)
    await redis_store.set_metadata(session_id, "created_at", "2026-05-22")
    await redis_store.set_metadata(session_id, "owner_id", "anonymous")

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
            logger.error("Failed to connect MCP: %s", e)
            return

        config = AgentFactory.create("soc_analyst", catalog=catalog, memory=redis_store)._config
        
        # We manually run the loop and print the response
        llm = LLMClient(
            model=config.llm.model,
            temperature=config.llm.temperature,
            max_tokens=config.llm.max_tokens,
            cache_enabled=False # Disable cache to see real behavior
        )
        
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
        prompt = f"""
Sen otonom bir Tier 1 (T1) SOC Analistisin. SIEM'den aşağıdaki alarm düştü:

ALARM DETAYLARI:
{alert_details}

GÖREVİN:
Bu alarmı analiz et, gerekli bağlamı topla, False Positive (FP) / True Positive (TP) ayrımını yap ve gerekirse olayı sınırlandırıp (containment) vaka oluştur. Aşağıdaki standart iş akışlarına (workflows) göre hareket etmelisin:

1. ZARARLI YAZILIM / MALWARE AKIŞI (Execution/Persistence):
   - Eğer alarm bir zararlı dosya veya sysmon process creation içeriyorsa, dosya hash'ini `get_file_reputation` ile kontrol et.
   - Duruma göre cihazdaki son aktiviteleri `query_siem_logs` ile incele.
   - Zararlı (Malicious) olduğuna karar verirsen `create_case` ile kritik vaka aç ve cihazı `isolate_endpoint` ile ağdan izole et.

2. BRUTE FORCE / COMPROMISED ACCOUNT AKIŞI (Credential Access):
   - IP repütasyonunu `get_ip_reputation` ile kontrol et.
   - Başarılı giriş var mı `query_siem_logs` ile bak.
   - Kullanıcı `get_ad_user_info` ile bak.
   - Duruma göre kısıtla.

3. COMMAND & CONTROL (C2):
   - Domain repütasyonunu `get_domain_url_reputation` ile kontrol et.

4. OS CREDENTIAL DUMPING AKIŞI (T1003):
   - /etc/shadow veya kimlik bilgisi erişimi varsa `find_playbook_for_alert` ile uygun playbook'u bul.
   - `trigger_playbook` ile playbook'u çalıştır ve adımlarını takip et.
"""

        # Filter tools
        matched_tools = [t for t in catalog.all_tools() if t.name in config.tool_filters.names]
        tool_schemas = [t.to_openai_schema() for t in matched_tools]
        tool_map = {t.name: t for t in matched_tools}

        messages = [
            {"role": "system", "content": config.system_prompt_override or ""},
            {"role": "user", "content": prompt}
        ]

        logger.info("Starting manual ReAct loop...")
        for iteration in range(1, 10):
            logger.info("--- ITERATION %d ---", iteration)
            response = await llm.chat(messages, tools=tool_schemas or None)
            logger.info("Raw response from LLM wrapper: %s", json.dumps(response, indent=2))
            
            content = response.get("content")
            tool_calls = response.get("tool_calls")
            
            if not tool_calls:
                logger.info("No tool calls. Terminating loop. Final Answer is: %s", content)
                break
                
            messages.append({"role": "assistant", **response})
            
            # Execute tool calls
            for tc in tool_calls:
                tname = tc["function"]["name"]
                targs = json.loads(tc["function"]["arguments"])
                tool = tool_map[tname]
                logger.info("Executing tool %s with args %s...", tname, targs)
                
                # Execute tool
                result = await tool.execute(**targs)
                logger.info("Tool output: %s", result.output)
                
                tool_msg = {
                    "role": "tool",
                    "tool_call_id": tc["id"],
                    "name": tname,
                    "content": str(result.output)
                }
                messages.append(tool_msg)

    await redis_store.close()
    logger.info("Done.")

if __name__ == "__main__":
    asyncio.run(run_debug())
