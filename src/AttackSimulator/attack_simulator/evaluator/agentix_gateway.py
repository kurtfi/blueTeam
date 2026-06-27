"""
Gateway to query Agentix core sessions and session_events APIs.
Isolates AttackSimulator from direct Agentix database dependencies by communicating over HTTP REST APIs.
"""

import os
from typing import Any

import httpx
import structlog
from attack_simulator.config import INTERNAL_API_KEY, WEBHOOK_URL

logger = structlog.get_logger(__name__)


class AgentixSessionGateway:
    """
    Gateway to query Agentix sessions and session events over HTTP.
    """

    def __init__(self, base_url: str | None = None, api_key: str | None = None) -> None:
        # Derive agentix base url from WEBHOOK_URL or env override
        derived_base = WEBHOOK_URL.split("/v1/")[0] if "/v1/" in WEBHOOK_URL else "http://localhost:8080"
        self.base_url = base_url or os.getenv("AGENTIX_API_URL", derived_base)
        self.api_key = api_key or INTERNAL_API_KEY

    async def get_session_status(self, session_id: str, conn: Any | None = None) -> str | None:
        """
        Retrieves the status of an Agentix session.
        """
        # Note: conn parameter is ignored, kept for backward compatibility signature
        url = f"{self.base_url}/v1/sessions/{session_id}"
        headers = {}
        if self.api_key:
            headers["X-Internal-API-Key"] = self.api_key

        verify_ssl = os.getenv("ATTACK_SIMULATOR_VERIFY_SSL", "True").lower() == "true"

        async with httpx.AsyncClient(verify=verify_ssl) as client:
            try:
                resp = await client.get(url, headers=headers, timeout=10.0)
                if resp.status_code == 200:
                    data = resp.json()
                    return data.get("status")
                logger.warn("agentix_gateway.get_session_status_unexpected_response", session_id=session_id, status_code=resp.status_code)
                return None
            except Exception as e:
                logger.error("agentix_gateway.get_session_status_failed", session_id=session_id, error=str(e))
                return None

    async def get_session_events(self, session_id: str, conn: Any | None = None) -> list[dict[str, Any]]:
        """
        Retrieves event logs for a given session.
        """
        # Note: conn parameter is ignored, kept for backward compatibility signature
        url = f"{self.base_url}/v1/sessions/{session_id}/events"
        headers = {}
        if self.api_key:
            headers["X-Internal-API-Key"] = self.api_key

        verify_ssl = os.getenv("ATTACK_SIMULATOR_VERIFY_SSL", "True").lower() == "true"

        async with httpx.AsyncClient(verify=verify_ssl) as client:
            try:
                resp = await client.get(url, headers=headers, timeout=10.0)
                if resp.status_code == 200:
                    return resp.json()
                logger.warn("agentix_gateway.get_session_events_unexpected_response", session_id=session_id, status_code=resp.status_code)
                return []
            except Exception as e:
                logger.error("agentix_gateway.get_session_events_failed", session_id=session_id, error=str(e))
                return []

    async def get_session_details(self, session_id: str) -> dict[str, Any] | None:
        """
        Retrieves all details for an Agentix session.
        """
        url = f"{self.base_url}/v1/sessions/{session_id}"
        headers = {}
        if self.api_key:
            headers["X-Internal-API-Key"] = self.api_key

        verify_ssl = os.getenv("ATTACK_SIMULATOR_VERIFY_SSL", "True").lower() == "true"

        async with httpx.AsyncClient(verify=verify_ssl) as client:
            try:
                resp = await client.get(url, headers=headers, timeout=10.0)
                if resp.status_code == 200:
                    return resp.json()
                logger.warn("agentix_gateway.get_session_details_unexpected_response", session_id=session_id, status_code=resp.status_code)
                return None
            except Exception as e:
                logger.error("agentix_gateway.get_session_details_failed", session_id=session_id, error=str(e))
                return None
