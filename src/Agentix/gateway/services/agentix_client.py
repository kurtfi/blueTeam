"""
Gateway ↔ Core Agentix HTTP client.

All requests to the internal Core API carry the shared secret via the
``X-Internal-Api-Key`` header.  Session-creation requests also propagate the
authenticated ``user_id`` so the Core can enforce ownership.
"""

import json
import os
from collections.abc import AsyncGenerator

import httpx
import structlog

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
                f"{AGENTIX_API_URL}/v1/session", json={"user_id": user_id}, headers=_internal_headers(), timeout=10.0
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
            except Exception as e:
                logger.warning("gateway.agentix_client.debug_write_failed", error=str(e))

            logger.info(
                "gateway.agentix_client.verify_owner_result",
                session_id=session_id,
                provided_user_id=user_id,
                actual_owner_id=owner_id,
                match=is_match,
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
                timeout=None,  # Wait for SSE stream
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


async def get_playbooks() -> str:
    """
    Fetch the cached playbooks markdown text from the Core API.
    """
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{AGENTIX_API_URL}/v1/playbooks", headers=_internal_headers(), timeout=5.0)
            response.raise_for_status()
            data = response.json()
            return str(data.get("playbooks_markdown", ""))
        except Exception as e:
            logger.error("gateway.agentix_client.get_playbooks_failed", error=str(e))
            return ""


async def get_playbooks_summary() -> list:
    """
    Fetch the cached playbooks JSON summary from the Core API.
    """
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                f"{AGENTIX_API_URL}/v1/playbooks/summary", headers=_internal_headers(), timeout=5.0
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error("gateway.agentix_client.get_playbooks_summary_failed", error=str(e))
            return []


async def get_playbook_details(playbook_id: str) -> dict:
    """
    Fetch the details of a specific playbook by ID from the Core API.
    """
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                f"{AGENTIX_API_URL}/v1/playbooks/{playbook_id}", headers=_internal_headers(), timeout=5.0
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error("gateway.agentix_client.get_playbook_details_failed", playbook_id=playbook_id, error=str(e))
            raise


async def list_sessions(
    owner_id: str | None = None,
    source: str | None = None,
    status: str | None = None,
    search: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """
    Fetch list of sessions from Core API with filters.
    """
    params: dict[str, str | int] = {}
    if owner_id:
        params["owner_id"] = owner_id
    if source:
        params["source"] = source
    if status:
        params["status"] = status
    if search:
        params["search"] = search
    params["limit"] = limit
    params["offset"] = offset

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                f"{AGENTIX_API_URL}/v1/sessions", params=params, headers=_internal_headers(), timeout=10.0
            )
            response.raise_for_status()
            total = int(response.headers.get("X-Total-Count", "0"))
            return {"sessions": response.json(), "total_count": total}
        except Exception as e:
            logger.error("gateway.agentix_client.list_sessions_failed", error=str(e))
            raise


async def get_session_detail(session_id: str) -> dict:
    """
    Fetch session details from Core API.
    """
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                f"{AGENTIX_API_URL}/v1/sessions/{session_id}", headers=_internal_headers(), timeout=10.0
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error("gateway.agentix_client.get_session_detail_failed", session_id=session_id, error=str(e))
            raise


async def get_session_workspace(session_id: str) -> dict:
    """
    Fetch session workspace stats from Core API.
    """
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                f"{AGENTIX_API_URL}/v1/session/{session_id}/workspace", headers=_internal_headers(), timeout=10.0
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error("gateway.agentix_client.get_session_workspace_failed", session_id=session_id, error=str(e))
            raise


async def get_session_events(session_id: str, limit: int = 100) -> list[dict]:
    """
    Fetch session audit events from Core API.
    """
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                f"{AGENTIX_API_URL}/v1/sessions/{session_id}/events",
                params={"limit": limit},
                headers=_internal_headers(),
                timeout=10.0,
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error("gateway.agentix_client.get_session_events_failed", session_id=session_id, error=str(e))
            raise


async def update_session_status(session_id: str, status: str, verdict: str | None = None) -> dict:
    """
    Update session status/verdict on Core API.
    """
    payload = {}
    if status:
        payload["status"] = status
    if verdict:
        payload["verdict"] = verdict

    async with httpx.AsyncClient() as client:
        try:
            response = await client.patch(
                f"{AGENTIX_API_URL}/v1/sessions/{session_id}", json=payload, headers=_internal_headers(), timeout=10.0
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error("gateway.agentix_client.update_session_status_failed", session_id=session_id, error=str(e))
            raise


async def get_session_stats() -> dict:
    """
    Fetch session aggregated stats from Core API.
    """
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                f"{AGENTIX_API_URL}/v1/sessions/stats", headers=_internal_headers(), timeout=10.0
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error("gateway.agentix_client.get_session_stats_failed", error=str(e))
            raise


async def approve_session(session_id: str) -> dict:
    """
    Approve the session action on Core API.
    """
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{AGENTIX_API_URL}/v1/sessions/{session_id}/approve", headers=_internal_headers(), timeout=10.0
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error("gateway.agentix_client.approve_session_failed", session_id=session_id, error=str(e))
            raise


async def reject_session(session_id: str) -> dict:
    """
    Reject the session action on Core API.
    """
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{AGENTIX_API_URL}/v1/sessions/{session_id}/reject", headers=_internal_headers(), timeout=10.0
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error("gateway.agentix_client.reject_session_failed", session_id=session_id, error=str(e))
            raise



