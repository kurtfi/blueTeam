# ruff: noqa: E501
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from gateway.security.auth import get_current_user
from gateway.services import agentix_client

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/web/sessions", tags=["Web Sessions API"])


class UpdateSessionRequest(BaseModel):
    status: str | None = None
    verdict: str | None = None


@router.get("", summary="Get all active sessions for the current user or admin")
async def list_sessions_endpoint(
    source: str | None = None,
    status_filter: str | None = None,
    limit: int = 50,
    offset: int = 0,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> list[dict]:
    user_id = str(current_user.get("uid", ""))
    role = str(current_user.get("role", "user"))

    # Non-admins can only see their own sessions
    owner_id_filter = None
    if role != "admin":
        owner_id_filter = user_id

    try:
        return await agentix_client.list_sessions(
            owner_id=owner_id_filter,
            source=source,
            status=status_filter,
            limit=limit,
            offset=offset,
        )
    except Exception as e:
        logger.error("gateway.routers.sessions.list_failed", uid=user_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve sessions list",
        )


@router.get("/stats", summary="Get aggregated session stats for dashboard")
async def get_stats_endpoint(
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict:
    try:
        return await agentix_client.get_session_stats()
    except Exception as e:
        logger.error("gateway.routers.sessions.stats_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve session statistics",
        )


@router.get("/{session_id}", summary="Get detailed session by ID")
async def get_session_endpoint(
    session_id: str,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict:
    user_id = str(current_user.get("uid", ""))
    role = str(current_user.get("role", "user"))

    try:
        # Retrieve session to check ownership
        sess = await agentix_client.get_session_detail(session_id)
        if role != "admin" and sess.get("owner_id") != user_id:
            logger.warning("gateway.routers.sessions.access_denied", session_id=session_id, uid=user_id)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to view this session.",
            )
        return sess
    except HTTPException:
        raise
    except Exception as e:
        logger.error("gateway.routers.sessions.detail_failed", session_id=session_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve session details",
        )


@router.get("/{session_id}/events", summary="Get audit events for a session")
async def get_events_endpoint(
    session_id: str,
    limit: int = 100,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> list[dict]:
    user_id = str(current_user.get("uid", ""))
    role = str(current_user.get("role", "user"))

    try:
        # Check ownership first
        sess = await agentix_client.get_session_detail(session_id)
        if role != "admin" and sess.get("owner_id") != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to view this session.",
            )
        return await agentix_client.get_session_events(session_id, limit=limit)
    except HTTPException:
        raise
    except Exception as e:
        logger.error("gateway.routers.sessions.events_failed", session_id=session_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve session events",
        )


@router.patch("/{session_id}", summary="Update session status or verdict")
async def update_session_endpoint(
    session_id: str,
    req: UpdateSessionRequest,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict:
    user_id = str(current_user.get("uid", ""))
    role = str(current_user.get("role", "user"))

    try:
        # Check ownership first
        sess = await agentix_client.get_session_detail(session_id)
        if role != "admin" and sess.get("owner_id") != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to modify this session.",
            )
            
        # Wazuh sessions can only be modified by admins (e.g. HITL approves)
        if sess.get("source") == "WAZUH" and role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only admin roles can interact with automated SIEM triage sessions.",
            )
            
        return await agentix_client.update_session_status(
            session_id=session_id,
            status=req.status,
            verdict=req.verdict,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("gateway.routers.sessions.update_failed", session_id=session_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update session status",
        )
