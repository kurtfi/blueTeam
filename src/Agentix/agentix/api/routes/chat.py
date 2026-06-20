import asyncio
import json

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from agentic_common.memory.redis_preferences import RedisPreferenceStore
from agentic_common.memory.redis_store import RedisSessionStore
from agentix.api.dependencies import get_catalog, get_pref_store, get_redis_store
from agentix.registry.catalog import ToolCatalog

logger = structlog.get_logger(__name__)
router = APIRouter()


class StreamRequest(BaseModel):
    session_id: str = Field(..., max_length=100)
    message: str = Field(..., max_length=1000)
    agent: str | None = Field(None, max_length=255)


@router.post("/chat/stream")
async def chat_stream(
    req: StreamRequest,
    request: Request,
    redis_store: RedisSessionStore = Depends(get_redis_store),
    catalog: ToolCatalog = Depends(get_catalog),
    pref_store: RedisPreferenceStore = Depends(get_pref_store),
):
    """
    Stream the ReAct reasoning loop (Thoughts, Observations, Answers)
    leveraging FastAPI StreamingResponse (Server-Sent Events).
    """
    if not req.message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty.")

    # Validate session existence
    if not await redis_store.exists(req.session_id):
        raise HTTPException(status_code=404, detail=f"Session '{req.session_id}' not found.")

    session_id = req.session_id
    task_manager = request.app.state.task_manager

    # Get or create subscriber queue for this client connection
    client_queue = await task_manager.get_or_create_queue(session_id)

    # Check if a task is already running for this session.
    # If not running, start it.
    is_running = await task_manager.is_running(session_id)
    if not is_running:
        start_run = request.app.state.start_session_background_run
        started = await start_run(
            session_id=session_id,
            message=req.message,
            agent=req.agent,
            redis_store=redis_store,
            catalog=catalog,
            pref_store=pref_store,
        )
        if not started:
            await task_manager.remove_queue(session_id, client_queue)
            raise HTTPException(status_code=409, detail="Session is currently executing another action.")

    async def _stream_generator():
        try:
            while True:
                item = await client_queue.get()
                if item.get("type") == "EOF":
                    break
                if "error" in item:
                    yield f"data: {json.dumps(item)}\n\n"
                    break
                json_data = json.dumps(item, default=str)
                yield f"data: {json_data}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            await task_manager.remove_queue(session_id, client_queue)

    return StreamingResponse(_stream_generator(), media_type="text/event-stream")
