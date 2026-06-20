"""
HTTP client to send correlated Wazuh alerts to the Agentix SIEM webhook endpoint.
"""

from typing import Any

import httpx
import structlog
from attack_simulator.config import INTERNAL_API_KEY, WEBHOOK_URL
from attack_simulator.mapper.wazuh_template import strip_information_leakage
from attack_simulator.sender.base import AlertSender

logger = structlog.get_logger(__name__)


class WebhookAlertSender(AlertSender):
    """
    Alert sender implementation that forwards payloads to the Agentix webhook API.
    """

    async def send(self, alert_payload: dict[str, Any], technique_id: str) -> str | None:
        # Safeguard: strip any information leakage before posting
        clean_payload = strip_information_leakage(alert_payload, technique_id)

        headers = {
            "Content-Type": "application/json",
        }

        # Authenticate via internal API key if configured
        if INTERNAL_API_KEY:
            headers["X-Internal-API-Key"] = INTERNAL_API_KEY

        async with httpx.AsyncClient(verify=False) as client:
            try:
                logger.debug(
                    "sender.posting_alert",
                    url=WEBHOOK_URL,
                    rule_id=clean_payload.get("rule", {}).get("id"),
                    mitre_id=clean_payload.get("rule", {}).get("mitre", {}).get("id"),
                )

                resp = await client.post(WEBHOOK_URL, json=clean_payload, headers=headers, timeout=10.0)

                if resp.status_code == 200:
                    data = resp.json()
                    session_id = data.get("session_id") or data.get("existing_session")
                    logger.info("sender.alert_sent_successfully", status=data.get("status"), session_id=session_id)
                    return str(session_id) if session_id else None
                else:
                    logger.error("sender.webhook_failed", status_code=resp.status_code, response=resp.text)
                    return None

            except Exception as e:
                logger.error("sender.connection_error", error=str(e))
                return None


# Standalone function for backward compatibility
async def send_alert_to_webhook(alert_payload: dict[str, Any]) -> str | None:
    """
    Sends a single alert payload to the configured Agentix webhook endpoint.
    Returns the created session_id from Agentix on success, or None on failure.
    """
    tech_id = "T1059"
    if "rule" in alert_payload and "mitre" in alert_payload["rule"]:
        ids = alert_payload["rule"]["mitre"].get("id", [])
        if ids:
            tech_id = ids[0]

    sender = WebhookAlertSender()
    return await sender.send(alert_payload, tech_id)
