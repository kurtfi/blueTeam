import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from gateway.security.firebase_auth import get_current_user
from gateway.services.agentix_client import create_session, stream_chat, verify_session_owner

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/web", tags=["Web API"])

class ChatRequest(BaseModel):
    message: str
    session_id: str | None = None
    agent: str | None = None

class ChatResponse(BaseModel):
    session_id: str

@router.post("/chat", summary="Start or continue a chat session")
async def web_chat(req: ChatRequest, current_user: dict = Depends(get_current_user)):
    """
    Standard Web endpoint to communicate with Agentix.
    It returns an SSE stream if requested or establishes a new session.
    """
    user_id = current_user.get("uid")
    
    # 1. Establish session if not provided
    session_id = req.session_id
    if not session_id:
        try:
            session_id = await create_session(user_id)
        except Exception as e:
            raise HTTPException(status_code=500, detail="Could not initialize session")
    else:
        # SECURITY: Verify session ownership to prevent IDOR attacks.
        # An authenticated user must own the session they're trying to access.
        is_owner = await verify_session_owner(session_id, user_id)
        if not is_owner:
            logger.warning(
                "gateway.web.idor_blocked",
                uid=user_id,
                session_id=session_id,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have access to this session.",
            )
            
    # 2. Return SSE Stream mapped directly from Core Agentix
    async def event_generator():
        import json
        try:
            # 2.1 Send the session_id to the client so they can reuse it
            yield f"data: {json.dumps({'type': 'session', 'session_id': session_id})}\n\n"

            async for step in stream_chat(session_id, req.message, req.agent):
                yield f"data: {json.dumps(step)}\n\n"
            yield "data: [DONE]\n\n"
        except Exception as e:
            logger.error("gateway.routers.web.stream_failed", error=str(e))
            yield f"data: {json.dumps({'error': 'Streaming failed'})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")

@router.get("/me", summary="Get current authenticated user info")
async def get_me(current_user: dict = Depends(get_current_user)):
    return {
        "uid": current_user.get("uid"),
        "role": current_user.get("role"),
        "email": current_user.get("email")
    }
