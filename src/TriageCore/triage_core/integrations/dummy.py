import os
import json
import httpx
import structlog
from typing import Optional

from triage_core.integrations.base import IFirewallProvider, IIamProvider, ISoarProvider

logger = structlog.get_logger(__name__)

class DummyFirewallProvider(IFirewallProvider):
    async def block_ip(self, ip_address: str) -> str:
        logger.info("provider.firewall.block_ip", ip_address=ip_address)
        fw_url = os.getenv("FIREWALL_API_URL", "")
        fw_key = os.getenv("FIREWALL_API_KEY", "")
        
        if not fw_url:
            return f"FIREWALL_API_URL not configured. Dummy action: IP {ip_address} successfully blocked."
            
        headers = {"Authorization": f"Bearer {fw_key}"}
        try:
            async with httpx.AsyncClient() as client:
                payload = {"action": "block", "ip": ip_address}
                resp = await client.post(f"{fw_url}/api/rules/block", json=payload, headers=headers, timeout=10.0)
                resp.raise_for_status()
                return f"IP {ip_address} blocked on firewall."
        except Exception as e:
            return f"Error blocking IP: {str(e)}"

class DummyIamProvider(IIamProvider):
    async def get_user_info(self, username: str) -> str:
        logger.info("provider.iam.get_user_info", username=username)
        idm_url = os.getenv("IDM_API_URL", "")
        idm_key = os.getenv("IDM_API_KEY", "")
        
        if not idm_url:
            return f"IDM_API_URL is not configured. Dummy Data -> User: {username} | Role: Standard | Status: Active"
            
        headers = {"Authorization": f"Bearer {idm_key}"}
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(f"{idm_url}/api/users/{username}", headers=headers, timeout=10.0)
                resp.raise_for_status()
                return f"User Info for {username}: {json.dumps(resp.json())}"
        except Exception as e:
            return f"Error getting user info: {str(e)}"

    async def disable_user_account(self, username: str) -> str:
        logger.info("provider.iam.disable_user_account", username=username)
        idm_url = os.getenv("IDM_API_URL", "")
        idm_key = os.getenv("IDM_API_KEY", "")
        
        if not idm_url:
            return f"IDM_API_URL not configured. Dummy action: User account {username} disabled."
            
        headers = {"Authorization": f"Bearer {idm_key}"}
        try:
            async with httpx.AsyncClient() as client:
                payload = {"status": "disabled", "reason": "Security Incident"}
                resp = await client.put(f"{idm_url}/api/users/{username}/status", json=payload, headers=headers, timeout=10.0)
                resp.raise_for_status()
                return f"User account {username} disabled successfully."
        except Exception as e:
            return f"Error disabling user account: {str(e)}"

class DummySoarProvider(ISoarProvider):
    async def trigger_workflow(self, workflow_id: str, data: Optional[dict] = None, webhook_url: str = "") -> str:
        logger.info("provider.soar.trigger_workflow", workflow_id=workflow_id, data=data)
        return f"SOAR workflow '{workflow_id}' triggered successfully (Dummy SOAR Provider)."
