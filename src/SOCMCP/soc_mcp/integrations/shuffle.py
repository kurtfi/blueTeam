import os
import httpx
import structlog
from typing import Optional, Dict, Any

from soc_mcp.integrations.base import ISoarProvider

logger = structlog.get_logger(__name__)

class ShuffleProvider(ISoarProvider):
    async def trigger_workflow(self, workflow_id: str, data: Optional[Dict[str, Any]] = None, webhook_url: str = "") -> str:
        logger.info("provider.shuffle.trigger_workflow", workflow_id=workflow_id)
        shuffle_url = os.getenv("SHUFFLE_URL", "http://shuffle-backend:5001")
        shuffle_api_key = os.getenv("SHUFFLE_API_KEY", "")

        if not webhook_url:
            webhook_base = os.getenv("SHUFFLE_WEBHOOK_BASE_URL", f"{shuffle_url}/api/v1/hooks")
            webhook_url = f"{webhook_base}/webhook_{workflow_id}"

        payload = data or {}
        payload["_agentix_source"] = "soc-agent"
        payload["_workflow_id"] = workflow_id

        headers: dict = {"Content-Type": "application/json"}
        if shuffle_api_key:
            headers["Authorization"] = f"Bearer {shuffle_api_key}"

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    webhook_url,
                    json=payload,
                    headers=headers,
                    timeout=15.0,
                )
                if resp.status_code in (200, 201, 202):
                    return (
                        f"Shuffle workflow '{workflow_id}' triggered successfully.\n"
                        f"Webhook URL: {webhook_url}\n"
                        f"Response: {resp.status_code}"
                    )
                else:
                    return (
                        f"Unexpected Shuffle webhook response: {resp.status_code}\n"
                        f"Body: {resp.text[:300]}"
                    )
        except Exception as e:
            logger.error("shuffle.trigger.error", error=str(e))
            return f"Error triggering Shuffle workflow: {str(e)}"
