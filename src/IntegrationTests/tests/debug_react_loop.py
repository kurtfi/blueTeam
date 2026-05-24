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

# Configure logging to stdout
logging.basicConfig(level=logging.INFO, stream=sys.stdout,
                    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("debug_react_loop")

async def run_debug():
    session_id = "debug-react-loop-test"
    logger.info("Initializing RedisSessionStore...")
    redis_store = RedisSessionStore(redis_url=settings.redis_url)
    
    logger.info("Clearing session %s...", session_id)
    await redis_store.clear(session_id)
    
    logger.info("Setting metadata for session %s...", session_id)
    await redis_store.set_metadata(session_id, "created_at", "2026-05-22")
    await redis_store.set_metadata(session_id, "owner_id", "anonymous")

    catalog = ToolCatalog()
    
    async with AsyncExitStack() as stack:
        try:
            logger.info("Connecting to General MCP: %s...", settings.agentix_general_mcp_url)
            gen_transport = await stack.enter_async_context(sse_client(settings.agentix_general_mcp_url))
            gen_read, gen_write = gen_transport
            gen_session = await stack.enter_async_context(ClientSession(gen_read, gen_write))
            await gen_session.initialize()
            await catalog.register_mcp_client(gen_session)
            
            logger.info("Connecting to SOC MCP: %s...", settings.agentix_soc_mcp_url)
            soc_transport = await stack.enter_async_context(sse_client(settings.agentix_soc_mcp_url))
            soc_read, soc_write = soc_transport
            soc_session = await stack.enter_async_context(ClientSession(soc_read, soc_write))
            await soc_session.initialize()
            await catalog.register_mcp_client(soc_session)
            
            logger.info("MCP tools synced. Total tools registered: %d", len(catalog.all_tools()))
        except Exception as e:
            logger.error("Failed to connect/sync MCP tools: %s", e)
            return

        # Prepare payload
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
        
        # Build prompt
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
   - Başarısız girişler veya şüpheli girişler varsa, IP repütasyonunu `get_ip_reputation` ile kontrol et.
   - Başarılı bir giriş yapılıp yapılmadığını `query_siem_logs` ile teyit et.
   - İlgili kullanıcının bilgilerini `get_ad_user_info` ile al.
   - Başarılı yetkisiz giriş varsa `disable_user_account` ile hesabı kilitle, `block_ip` ile IP'yi engelle ve vaka aç. Başarısız giriş ise sadece IP'yi engelle ve düşük seviyeli vaka aç.

3. COMMAND & CONTROL (C2) / ŞÜPHELİ AĞ TRAFİĞİ AKIŞI:
   - Dış ağa şüpheli bir DNS/HTTP isteği varsa, hedef domain/IP repütasyonunu `get_domain_url_reputation` ile kontrol et.
   - Bilinen bir C2 sunucusuysa hedefi `block_ip` ile engelle ve etkilenen makineyi `isolate_endpoint` ile izole et. Vaka aç.

4. OS OS CREDENTIAL DUMPING AKIŞI (T1003):
   - /etc/shadow veya kimlik bilgisi erişimi varsa `find_playbook_for_alert` ile uygun playbook'u bul.
   - `trigger_playbook` ile playbook'u çalıştır ve adımlarını takip et.

Tüm adımlarını sırasıyla planla, uygun MCP araçlarını kullan ve nihai kararla birlikte eylemlerini özetle.
"""

        logger.info("Initializing SOC Analyst agent...")
        orchestrator = AgentFactory.create(
            "soc_analyst",
            catalog=catalog,
            memory=redis_store
        )
        # Enable debug logs or output
        logger.info("Starting run_stream...")
        async for step in orchestrator.run_stream(session_id=session_id, user_message=prompt):
            logger.info("STEP YIELDED -> Type: %s, Tool: %s, Content: %s", 
                        step.step_type, step.tool_name, step.content)

    await redis_store.close()
    logger.info("Done.")

if __name__ == "__main__":
    asyncio.run(run_debug())
