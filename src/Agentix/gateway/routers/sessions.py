# ruff: noqa: E501
from datetime import datetime
from typing import Any
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from gateway.security.auth import get_current_user
from gateway.services import agentix_client

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/web/sessions", tags=["Web Sessions API"])


class SessionItem(BaseModel):
    id: UUID
    display_name: str
    source: str
    status: str
    owner_id: str
    agent_name: str | None = None
    siem_rule_id: str | None = None
    siem_rule_desc: str | None = None
    siem_severity: int | None = None
    source_ip: str | None = None
    mitre_ids: list[str] | None = None
    verdict: str | None = None
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None = None
    message_count: int
    tool_calls: int
    hitl_count: int
    langfuse_trace_id: str | None = None
    alert_payload: dict[str, Any] | None = None


class SessionsListResponse(BaseModel):
    sessions: list[SessionItem]
    total_count: int


class SessionStatsResponse(BaseModel):
    active_sessions: int
    pending_hitl: int
    created_last_24h: int
    completed_sessions: int
    siem_sessions: int
    user_sessions: int
    true_positives: int
    false_positives: int
    undetermined: int
    avg_duration_seconds: float


class SessionEventItem(BaseModel):
    id: int
    session_id: UUID
    event_type: str
    actor: str
    content: str | None = None
    metadata: dict[str, Any] | None = None
    created_at: datetime


class SessionCreateResponse(BaseModel):
    session_id: UUID


class SessionActionResponse(BaseModel):
    status: str
    message: str | None = None


class SessionWorkspaceResponse(BaseModel):
    session_id: UUID
    workspace: dict[str, Any] | None = None
    message: str | None = None


class UpdateSessionRequest(BaseModel):
    status: str | None = None
    verdict: str | None = None


@router.get(
    "",
    response_model=SessionsListResponse,
    summary="Get all active sessions for the current user or admin",
)
async def list_sessions_endpoint(
    source: str | None = None,
    status_filter: str | None = None,
    search: str | None = None,
    limit: int = 50,
    offset: int = 0,
    current_user: dict[str, Any] = Depends(get_current_user),
):
    user_id = str(current_user.get("uid", ""))
    role = str(current_user.get("role", "user"))

    # Non-admins can only see their own sessions
    owner_id_filter = None
    if role != "admin":
        owner_id_filter = user_id

    try:
        res = await agentix_client.list_sessions(
            owner_id=owner_id_filter,
            source=source,
            status=status_filter,
            search=search,
            limit=limit,
            offset=offset,
        )
        return {"sessions": res["sessions"], "total_count": res["total_count"]}
    except Exception as e:
        logger.error("gateway.routers.sessions.list_failed", uid=user_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve sessions list",
        )


@router.get(
    "/stats",
    response_model=SessionStatsResponse,
    summary="Get aggregated session stats for dashboard",
)
async def get_stats_endpoint(
    current_user: dict[str, Any] = Depends(get_current_user),
):
    try:
        return await agentix_client.get_session_stats()
    except Exception as e:
        logger.error("gateway.routers.sessions.stats_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve session statistics",
        )


@router.get(
    "/{session_id}",
    response_model=SessionItem,
    summary="Get detailed session by ID",
)
async def get_session_endpoint(
    session_id: str,
    current_user: dict[str, Any] = Depends(get_current_user),
):
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


@router.get(
    "/{session_id}/events",
    response_model=list[SessionEventItem],
    summary="Get audit events for a session",
)
async def get_events_endpoint(
    session_id: str,
    limit: int = 100,
    current_user: dict[str, Any] = Depends(get_current_user),
):
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


@router.patch(
    "/{session_id}",
    response_model=SessionActionResponse,
    summary="Update session status or verdict",
)
async def update_session_endpoint(
    session_id: str,
    req: UpdateSessionRequest,
    current_user: dict[str, Any] = Depends(get_current_user),
):
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

        # SIEM sessions can only be modified by admins (e.g. HITL approves)
        if sess.get("source") == "SIEM" and role != "admin":
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


@router.post(
    "/{session_id}/approve",
    response_model=SessionActionResponse,
    summary="Approve a pending action for a session",
)
async def approve_session_endpoint(
    session_id: str,
    current_user: dict[str, Any] = Depends(get_current_user),
):
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

        # SIEM sessions can only be modified by admins
        if sess.get("source") == "SIEM" and role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only admin roles can interact with automated SIEM triage sessions.",
            )

        return await agentix_client.approve_session(session_id)
    except HTTPException:
        raise
    except Exception as e:
        logger.error("gateway.routers.sessions.approve_failed", session_id=session_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to approve session action",
        )


@router.post(
    "/{session_id}/reject",
    response_model=SessionActionResponse,
    summary="Reject a pending action for a session",
)
async def reject_session_endpoint(
    session_id: str,
    current_user: dict[str, Any] = Depends(get_current_user),
):
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

        # SIEM sessions can only be modified by admins
        if sess.get("source") == "SIEM" and role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only admin roles can interact with automated SIEM triage sessions.",
            )

        return await agentix_client.reject_session(session_id)
    except HTTPException:
        raise
    except Exception as e:
        logger.error("gateway.routers.sessions.reject_failed", session_id=session_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to reject session action",
        )


@router.post(
    "",
    response_model=SessionCreateResponse,
    summary="Create a new user chat session",
)
async def create_session_endpoint(
    current_user: dict[str, Any] = Depends(get_current_user),
):
    user_id = str(current_user.get("uid", ""))
    try:
        session_id = await agentix_client.create_session(user_id)
        return {"session_id": session_id}
    except Exception as e:
        logger.error("gateway.routers.sessions.create_failed", uid=user_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create new session",
        )


@router.get(
    "/{session_id}/workspace",
    response_model=SessionWorkspaceResponse,
    summary="Get workspace usage stats for a session",
)
async def get_session_workspace_endpoint(
    session_id: str,
    current_user: dict[str, Any] = Depends(get_current_user),
):
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
        return await agentix_client.get_session_workspace(session_id)
    except HTTPException:
        raise
    except Exception as e:
        logger.error("gateway.routers.sessions.workspace_failed", session_id=session_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve session workspace statistics",
        )
