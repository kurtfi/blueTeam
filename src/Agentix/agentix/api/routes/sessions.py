import uuid
from datetime import datetime
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response
from pydantic import BaseModel, Field

from agentic_common.memory import postgres_session_repo
from agentic_common.memory.redis_store import RedisSessionStore
from agentic_common.settings import settings
from agentic_common.workspace import SessionWorkspace
from agentix.api.dependencies import get_catalog, get_pref_store, get_redis_store

logger = structlog.get_logger(__name__)
router = APIRouter()


class CreateSessionRequest(BaseModel):
    user_id: str = Field("anonymous", max_length=255)


class SessionResponse(BaseModel):
    session_id: str
    message: str
    workspace_enabled: bool = False


class UpdateSessionRequest(BaseModel):
    status: str | None = Field(None, max_length=50)
    verdict: str | None = Field(None, max_length=50)


@router.post("/session", response_model=SessionResponse)
async def create_session(
    req: CreateSessionRequest | None = None, redis_store: RedisSessionStore = Depends(get_redis_store)
):
    """
    Initialize a new session and receive a unique UUID.
    This UUID should be passed in subsequent requests.
    Optionally provide a user_id for workspace ownership.
    """
    user_id = req.user_id if req else "anonymous"
    new_uuid = str(uuid.uuid4())

    # Create persistent session in PostgreSQL first
    display_name = f"User Chat — {datetime.now().strftime('%b %d %H:%M')}"
    try:
        await postgres_session_repo.create_session(
            session_id=new_uuid,
            display_name=display_name,
            source="USER",
            owner_id=user_id,
        )
    except Exception as e:
        logger.critical(
            "session.postgres_creation_failed", session_id=new_uuid, error=str(e), alert=True, db_failure=True
        )
        raise HTTPException(status_code=500, detail=f"Failed to persist session in Database: {str(e)}")

    # Register the session in the Redis store
    await redis_store.set_metadata(new_uuid, "created_at", datetime.now().isoformat())
    await redis_store.set_metadata(new_uuid, "owner_id", user_id)

    # Initialize session workspace (if enabled)
    workspace_enabled = False
    if settings.agentix_session_workspace_enabled:
        workspace = SessionWorkspace(session_id=new_uuid, owner_id=user_id)
        await workspace.initialize()
        workspace_enabled = True

    logger.info("session.created", session_id=new_uuid, owner=user_id)
    return SessionResponse(
        session_id=new_uuid,
        message="Session created successfully. Use this ID for /chat/stream",
        workspace_enabled=workspace_enabled,
    )


@router.post("/sessions/{session_id}/approve")
async def approve_session(
    request: Request,
    session_id: str = Path(..., max_length=100),
    redis_store: RedisSessionStore = Depends(get_redis_store),
    catalog: Any = Depends(get_catalog),
    pref_store: Any = Depends(get_pref_store),
):
    """
    REST API endpoint to approve the pending action of a session.
    Triggers resumption in a background task and returns immediately.
    """
    session = await postgres_session_repo.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")

    if session.get("status") != "WAITING_APPROVAL":
        raise HTTPException(
            status_code=400,
            detail=f"Session '{session_id}' is not awaiting approval. Current status: {session.get('status')}",
        )

    start_run = request.app.state.start_session_background_run
    started = await start_run(
        session_id=session_id,
        message="yes",
        agent=session.get("agent_name"),
        redis_store=redis_store,
        catalog=catalog,
        pref_store=pref_store,
    )
    if not started:
        raise HTTPException(status_code=409, detail="Session is already executing another action.")

    return {"status": "success", "message": "Approval processed. Session execution resumed in background."}


@router.post("/sessions/{session_id}/reject")
async def reject_session(
    request: Request,
    session_id: str = Path(..., max_length=100),
    redis_store: RedisSessionStore = Depends(get_redis_store),
    catalog: Any = Depends(get_catalog),
    pref_store: Any = Depends(get_pref_store),
):
    """
    REST API endpoint to reject the pending action of a session.
    Triggers cancellation/completion in a background task and returns immediately.
    """
    session = await postgres_session_repo.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")

    if session.get("status") != "WAITING_APPROVAL":
        raise HTTPException(
            status_code=400,
            detail=f"Session '{session_id}' is not awaiting approval. Current status: {session.get('status')}",
        )

    start_run = request.app.state.start_session_background_run
    started = await start_run(
        session_id=session_id,
        message="no",
        agent=session.get("agent_name"),
        redis_store=redis_store,
        catalog=catalog,
        pref_store=pref_store,
    )
    if not started:
        raise HTTPException(status_code=409, detail="Session is already executing another action.")

    return {"status": "success", "message": "Rejection processed. Session execution resumed in background."}


@router.delete("/session/{session_id}")
async def destroy_session(
    session_id: str = Path(..., max_length=100), redis_store: RedisSessionStore = Depends(get_redis_store)
):
    """
    Clean up a session's workspace (temp + downloads) and optionally destroy it entirely.
    """
    if not await redis_store.exists(session_id):
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")

    workspace = SessionWorkspace.from_session_id(session_id)
    result: dict = {"session_id": session_id}

    if workspace:
        cleanup_result = await workspace.cleanup()
        result["workspace_cleanup"] = cleanup_result
    else:
        result["workspace_cleanup"] = "No workspace found."

    await redis_store.clear(session_id)
    result["session_cleared"] = True

    logger.info("session.destroyed", session_id=session_id)
    return result


@router.get("/session/{session_id}/workspace")
async def get_workspace_info(
    session_id: str = Path(..., max_length=100), redis_store: RedisSessionStore = Depends(get_redis_store)
):
    """
    Return workspace usage statistics for a session.
    """
    if not await redis_store.exists(session_id):
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")

    workspace = SessionWorkspace.from_session_id(session_id)
    if workspace is None:
        return {"session_id": session_id, "workspace": None, "message": "No workspace found."}

    usage = await workspace.get_usage()
    # Strip internal path info — only expose session_id-relative stats
    usage.pop("root", None)
    return {"session_id": session_id, "workspace": usage}


@router.get("/session/{session_id}/owner")
async def get_session_owner(
    session_id: str = Path(..., max_length=100), redis_store: RedisSessionStore = Depends(get_redis_store)
):
    """
    Return the owner_id for a given session.
    Used by the Gateway to verify session ownership (IDOR prevention).
    """
    if not await redis_store.exists(session_id):
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")

    owner_id = await redis_store.get_metadata(session_id, "owner_id")
    return {"session_id": session_id, "owner_id": owner_id or "anonymous"}


@router.get("/sessions")
async def list_sessions(
    response: Response,
    source: str | None = Query(None, max_length=255),
    status: str | None = Query(None, max_length=255),
    owner_id: str | None = Query(None, max_length=255),
    search: str | None = Query(None, max_length=255),
    agent_name: str | None = Query(None, max_length=255),
    limit: int = 50,
    offset: int = 0,
):
    try:
        total = await postgres_session_repo.count_sessions(
            source=source,
            status=status,
            owner_id=owner_id,
            search=search,
            agent_name=agent_name,
        )
        response.headers["X-Total-Count"] = str(total)
        return await postgres_session_repo.list_sessions(
            source=source,
            status=status,
            owner_id=owner_id,
            search=search,
            agent_name=agent_name,
            limit=limit,
            offset=offset,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sessions/stats")
async def get_session_stats():
    try:
        return await postgres_session_repo.get_session_stats()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sessions/{session_id}")
async def get_session(session_id: str = Path(..., max_length=100)):
    try:
        session = await postgres_session_repo.get_session(session_id)
        if not session:
            raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")
        return session
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/sessions/{session_id}")
async def update_session(req: UpdateSessionRequest, session_id: str = Path(..., max_length=100)):
    try:
        session = await postgres_session_repo.get_session(session_id)
        if not session:
            raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")

        if req.status:
            valid_statuses = {"ACTIVE", "WAITING_APPROVAL", "COMPLETED", "FAILED", "ARCHIVED"}
            if req.status.upper() not in valid_statuses:
                raise HTTPException(status_code=400, detail=f"Invalid status: {req.status}")

            verdict_val = None
            if req.verdict:
                valid_verdicts = {"TRUE_POSITIVE", "FALSE_POSITIVE", "UNDETERMINED"}
                if req.verdict.upper() not in valid_verdicts:
                    raise HTTPException(status_code=400, detail=f"Invalid verdict: {req.verdict}")
                verdict_val = req.verdict.upper()

            await postgres_session_repo.update_status(session_id, req.status.upper(), verdict_val)

            await postgres_session_repo.add_event(
                session_id=session_id,
                event_type="status_change",
                actor="system",
                content=f"Session status updated to {req.status.upper()}"
                + (f" with verdict {verdict_val}" if verdict_val else ""),
            )

        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sessions/{session_id}/events")
async def get_session_events(session_id: str = Path(..., max_length=100), limit: int = 100):
    try:
        session = await postgres_session_repo.get_session(session_id)
        if not session:
            raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")
        return await postgres_session_repo.get_events(session_id, limit=limit)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
