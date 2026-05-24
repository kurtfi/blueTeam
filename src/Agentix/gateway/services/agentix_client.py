"""
Gateway ↔ Core Agentix HTTP client.

All requests to the internal Core API carry the shared secret via the
``X-Internal-Api-Key`` header.  Session-creation requests also propagate the
authenticated ``user_id`` so the Core can enforce ownership.
"""
import json
import httpx
import structlog
import os
from typing import AsyncGenerator

logger = structlog.get_logger(__name__)

AGENTIX_API_URL = os.getenv("AGENTIX_API_URL", "http://localhost:8000")
AGENTIX_INTERNAL_API_KEY = os.getenv("AGENTIX_INTERNAL_API_KEY", "")

def _internal_headers() -> dict[str, str]:
    """Build headers that authenticate with the Core API."""
    headers: dict[str, str] = {}
    if AGENTIX_INTERNAL_API_KEY:
        headers["X-Internal-Api-Key"] = AGENTIX_INTERNAL_API_KEY
    return headers


async def create_session(user_id: str) -> str:
    """
    Creates a session on the Core Agentix server on behalf of the user.
    """
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{AGENTIX_API_URL}/v1/session",
                json={"user_id": user_id},
                headers=_internal_headers(),
                timeout=10.0
            )
            response.raise_for_status()
            data = response.json()
            return data.get("session_id")
        except httpx.HTTPError as e:
            logger.error("gateway.agentix_client.create_session_failed", error=str(e))
            raise


async def verify_session_owner(session_id: str, user_id: str) -> bool:
    """
    Ask the Core API whether *user_id* owns *session_id*.

    Returns True if the user is the owner, False otherwise.
    Falls back to True if the ownership endpoint is unavailable (graceful
    degradation during migration).
    """
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                f"{AGENTIX_API_URL}/v1/session/{session_id}/owner",
                headers=_internal_headers(),
                timeout=5.0,
            )
            if response.status_code == 404:
                return False
            response.raise_for_status()
            data = response.json()
            owner_id = data.get("owner_id")
            
            is_match = owner_id == user_id
            
            # Temporary debug write to ensure we see the IDs regardless of logging config
            try:
                with open("gateway_ownership_debug.log", "a") as f:
                    f.write(f"Session: {session_id} | Provided: {user_id} | Actual: {owner_id} | Match: {is_match}\n")
            except:
                pass

            logger.info(
                "gateway.agentix_client.verify_owner_result",
                session_id=session_id,
                provided_user_id=user_id,
                actual_owner_id=owner_id,
                match=is_match
            )
            return is_match
        except httpx.HTTPError as e:
            logger.error(
                "gateway.agentix_client.verify_owner_failed",
                session_id=session_id,
                error=str(e),
            )
            # Fail-closed: deny access if we can't verify
            return False


async def stream_chat(session_id: str, message: str, agent: str | None = None) -> AsyncGenerator[dict, None]:
    """
    Streams the chat from the Core Agentix SSE endpoint.
    Yields parsed JSON chunks.
    """
    payload = {"session_id": session_id, "message": message}
    if agent:
        payload["agent"] = agent
        
    async with httpx.AsyncClient() as client:
        try:
            async with client.stream(
                "POST", 
                f"{AGENTIX_API_URL}/v1/chat/stream",
                json=payload,
                headers=_internal_headers(),
                timeout=None # Wait for SSE stream
            ) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data_str = line[6:]
                        if data_str == "[DONE]":
                            break
                        try:
                            yield json.loads(data_str)
                        except json.JSONDecodeError:
                            logger.warning("gateway.agentix_client.json_decode_error", data=data_str)
        except httpx.HTTPError as e:
            logger.error("gateway.agentix_client.stream_chat_failed", error=str(e))
            raise

async def ask_agentix_aggregated(user_id: str, message: str, session_id: str | None = None) -> str:
    """
    Utility for Webhooks (like Telegram) to get a full aggregated response
    rather than an SSE stream.
    """
    if not session_id:
        session_id = await create_session(user_id)
        
    aggregated_response = []
    
    try:
        async for step in stream_chat(session_id, message):
            # For this simple aggregation, we extract the "content" of the last steps, 
            # or specifically the Answer steps. You can customize this logic based on ReActStep types.
            if step.get("type") == "answer":
                aggregated_response.append(step.get("content", ""))
            elif step.get("type") == "thought":
                # Maybe we don't want to show thoughts to Telegram users, or maybe we do.
                pass
                
    except Exception as e:
        logger.error("gateway.agentix_client.aggregation_failed", error=str(e))
        return "Sorry, a system error occurred."
        
    return "\n".join(aggregated_response) if aggregated_response else "No response generated."
