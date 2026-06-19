import os

import httpx
import structlog
from fastapi import APIRouter, HTTPException, Request, Response

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/v1/webhooks", tags=["Webhooks"])

AGENTIX_API_URL = os.getenv("AGENTIX_API_URL", "http://localhost:8000")


@router.post("/siem")
async def siem_webhook(request: Request):
    """
    Gateway endpoint for receiving SIEM alerts.
    Forwards the request body and signature header to agentix-api.
    """
    body = await request.body()
    headers = dict(request.headers)

    # We should exclude Host header to let httpx determine it or pass it correctly
    headers.pop("host", None)

    # Forward the POST request to agentix-api
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(f"{AGENTIX_API_URL}/v1/webhooks/siem", content=body, headers=headers, timeout=10.0)
            # Return the exact response from agentix-api
            return Response(content=resp.content, status_code=resp.status_code, headers=dict(resp.headers))
        except httpx.HTTPError as e:
            logger.error("gateway.webhooks.forward_failed", error=str(e))
            raise HTTPException(status_code=502, detail="Error forwarding request to agentix-api")


@router.post("/simulation")
async def simulation_webhook(request: Request):
    """
    Gateway endpoint for receiving Simulation alerts.
    Forwards the request body and signature header to agentix-api.
    """
    body = await request.body()
    headers = dict(request.headers)

    # We should exclude Host header to let httpx determine it or pass it correctly
    headers.pop("host", None)

    # Forward the POST request to agentix-api
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(f"{AGENTIX_API_URL}/v1/webhooks/simulation", content=body, headers=headers, timeout=10.0)
            # Return the exact response from agentix-api
            return Response(content=resp.content, status_code=resp.status_code, headers=dict(resp.headers))
        except httpx.HTTPError as e:
            logger.error("gateway.webhooks.forward_simulation_failed", error=str(e))
            raise HTTPException(status_code=502, detail="Error forwarding request to agentix-api")
