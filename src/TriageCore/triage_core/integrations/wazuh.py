import json
import os

import httpx
import structlog
from triage_core.integrations.base import IEndpointProvider, ISiemProvider

logger = structlog.get_logger(__name__)

class WazuhProvider(ISiemProvider, IEndpointProvider):
    async def query_logs(self, query: str, time_range: str = "last 1 hour") -> str:
        logger.info("provider.wazuh.query_logs", query=query, time_range=time_range)
        es_url = os.getenv("ELASTICSEARCH_URL", "http://wazuh-indexer:9200")
        es_user = os.getenv("ELASTICSEARCH_USER")
        es_pass = os.getenv("ELASTICSEARCH_PASSWORD")
        if not es_user or not es_pass:
            return "SIEM query failed: ELASTICSEARCH_USER or ELASTICSEARCH_PASSWORD not configured."
        verify_ssl = os.getenv("WAZUH_API_VERIFY_SSL", "false").lower() in ("true", "1", "yes")
        
        try:
            async with httpx.AsyncClient(verify=verify_ssl) as client:
                # Escape Lucene special characters except fields (:), wildcards (*, ?), and phrases (")
                escape_chars = r'+-=&|><!(){}[]^~\\/'
                safe_query = ''.join(['\\' + c if c in escape_chars else c for c in query])
                
                payload = {
                    "query": {
                        "query_string": {
                            "query": safe_query
                        }
                    },
                    "size": 10,
                    "sort": [{"@timestamp": {"order": "desc"}}]
                }
                # Wazuh alerts index format
                resp = await client.post(
                    f"{es_url}/wazuh-alerts-*/_search",
                    json=payload,
                    auth=(es_user, es_pass),
                    timeout=15.0
                )
                resp.raise_for_status()
                hits = resp.json().get("hits", {}).get("hits", [])
                if not hits:
                    return f"No events found for query '{query}' in {time_range}."
                
                results = []
                for hit in hits:
                    src = hit.get("_source", {})
                    rule = src.get("rule", {}).get("description", "Unknown Rule")
                    results.append(f"[{src.get('@timestamp')}] Rule: {rule} | Data: {json.dumps(src.get('data', {}))}")
                    
                return f"Found {len(results)} events:\n" + "\n".join(results)
        except Exception as e:
            logger.error("wazuh.query.error", error=str(e))
            return f"SIEM query failed: {str(e)}"

    async def get_endpoint_info(self, agent_id: str) -> str:
        logger.info("provider.wazuh.get_endpoint_info", agent_id=agent_id)
        wazuh_url = os.getenv("WAZUH_API_URL", "https://wazuh-manager:55000")
        wazuh_user = os.getenv("WAZUH_API_USER")
        wazuh_pass = os.getenv("WAZUH_API_PASSWORD")
        if not wazuh_user or not wazuh_pass:
            return "Error getting endpoint info: WAZUH_API_USER or WAZUH_API_PASSWORD not configured."
        verify_ssl = os.getenv("WAZUH_API_VERIFY_SSL", "false").lower() in ("true", "1", "yes")

        try:
            async with httpx.AsyncClient(verify=verify_ssl) as client:
                auth_resp = await client.get(
                    f"{wazuh_url}/security/user/authenticate",
                    auth=(wazuh_user, wazuh_pass),
                    timeout=10.0,
                )
                auth_resp.raise_for_status()
                token = auth_resp.json().get("data", {}).get("token")
                headers = {"Authorization": f"Bearer {token}"}

                resp = await client.get(
                    f"{wazuh_url}/agents/{agent_id}",
                    headers=headers,
                    timeout=10.0,
                )
                resp.raise_for_status()
                agent_data = resp.json().get("data", {}).get("affected_items", [{}])[0]

                name = agent_data.get("name", "N/A")
                status = agent_data.get("status", "N/A")
                ip = agent_data.get("ip", "N/A")
                os_info = agent_data.get("os", {})
                os_str = f"{os_info.get('name', '')} {os_info.get('version', '')}".strip() or "N/A"
                last_seen = agent_data.get("lastKeepAlive", "N/A")
                version = agent_data.get("version", "N/A")
                groups = ", ".join(agent_data.get("group", []))

                return (
                    f"Endpoint Info – ID: {agent_id}\n"
                    f"  Hostname : {name}\n"
                    f"  IP       : {ip}\n"
                    f"  OS       : {os_str}\n"
                    f"  Status   : {status}\n"
                    f"  Version  : {version}\n"
                    f"  Groups   : {groups or 'default'}\n"
                    f"  Last Seen: {last_seen}"
                )
        except Exception as e:
            logger.error("wazuh.agent.info.error", error=str(e))
            return f"Error getting endpoint info: {str(e)}"

    async def isolate_endpoint(self, agent_id: str) -> str:
        logger.info("provider.wazuh.isolate_endpoint", agent_id=agent_id)
        wazuh_url = os.getenv("WAZUH_API_URL", "https://wazuh-manager:55000")
        wazuh_user = os.getenv("WAZUH_API_USER")
        wazuh_pass = os.getenv("WAZUH_API_PASSWORD")
        if not wazuh_user or not wazuh_pass:
            return "Error isolating endpoint: WAZUH_API_USER or WAZUH_API_PASSWORD not configured."
        wazuh_verify_ssl = os.getenv("WAZUH_API_VERIFY_SSL", "false").lower() in ("true", "1", "yes")
        
        try:
            async with httpx.AsyncClient(verify=wazuh_verify_ssl) as client:
                auth_resp = await client.get(f"{wazuh_url}/security/user/authenticate", auth=(wazuh_user, wazuh_pass))
                auth_resp.raise_for_status()
                token = auth_resp.json().get("data", {}).get("token")
                
                headers = {"Authorization": f"Bearer {token}"}
                
                payload = {
                    "command": "host-deny",
                    "custom": False,
                    "agents_list": [agent_id]
                }
                resp = await client.put(f"{wazuh_url}/active-response", json=payload, headers=headers)
                resp.raise_for_status()
                
                return f"Endpoint {agent_id} successfully isolated. Response: {json.dumps(resp.json())}"
        except Exception as e:
            logger.error("wazuh.ar.error", error=str(e))
            return f"Error isolating endpoint: {str(e)}"
