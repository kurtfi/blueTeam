"""
FastAPI Server for the Agentix platform.

Provides UUID-based session initialization and an SSE streaming endpoint
for interacting with the Agentix Orchestrator in real-time.
"""
from __future__ import annotations

import asyncio
import json
import uuid
from contextlib import AsyncExitStack
from datetime import datetime

import structlog
from agentic_common.memory import postgres_session_repo
from agentic_common.memory.redis_preferences import RedisPreferenceStore
from agentic_common.memory.redis_store import RedisSessionStore
from agentic_common.settings import settings
from agentic_common.workspace import SessionWorkspace
from agentix.api.internal_auth import InternalApiKeyMiddleware
from agentix.api.routes import webhooks
from agentix.core.alert_dedup import AlertDeduplicator
from agentix.core.cleanup import run_periodic_cleanup
from agentix.core.orchestrator import Orchestrator
from agentix.registry.catalog import ToolCatalog
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse
from mcp import ClientSession
from mcp.client.sse import sse_client
from pydantic import BaseModel

logger = structlog.get_logger(__name__)

# Initialize FastAPI App
app = FastAPI(
    title="Agentix AI Service",
    description="A streaming AI tool orchestrator",
    version="1.0.0",
)

# Internal API Key Authentication
app.add_middleware(InternalApiKeyMiddleware)

# Dependency functions
async def get_redis_store(request: Request) -> RedisSessionStore:
    return request.app.state.redis_store

async def get_catalog(request: Request) -> ToolCatalog:
    return request.app.state.catalog

async def get_pref_store(request: Request) -> RedisPreferenceStore:
    return request.app.state.pref_store

@app.on_event("startup")
async def startup_event():
    logger.info("Starting up Agentix Service...")
    
    # Run database migrations
    try:
        await postgres_session_repo.run_migrations()
        logger.info("Database migrations run successfully.")
    except Exception as e:
        logger.error("Failed to run database migrations", error=str(e))
        
    app.state.catalog = ToolCatalog()
    app.state.redis_store = RedisSessionStore(redis_url=settings.redis_url)
    app.state.pref_store = RedisPreferenceStore(redis_url=settings.redis_url)
    app.state.deduplicator = AlertDeduplicator(redis_url=settings.redis_url, window_seconds=120)
    app.state.mcp_stack = AsyncExitStack()
    
    # 2. Initialize SOC MCP Server Connection with retry logic
    max_retries = 15
    retry_delay = 5  # seconds
    for attempt in range(1, max_retries + 1):
        try:
            logger.info("Connecting to SOC MCP Server...", attempt=attempt, url=settings.agentix_triage_core_url)
            # Recreate stack for this attempt to ensure clean state
            app.state.mcp_stack = AsyncExitStack()
            
            soc_transport = await app.state.mcp_stack.enter_async_context(sse_client(settings.agentix_triage_core_url))
            soc_read, soc_write = soc_transport
            app.state.triage_core_session = await app.state.mcp_stack.enter_async_context(ClientSession(soc_read, soc_write))
            await app.state.triage_core_session.initialize()
            
            # Sync TriageCore Tools into our Catalog
            await app.state.catalog.register_mcp_client(app.state.triage_core_session)

            # Sync TriageCore Playbooks into our Catalog
            try:
                result = await app.state.triage_core_session.call_tool("list_playbooks")
                from agentix.tools.mcp_adapter import MCPToolAdapter
                playbooks_str = MCPToolAdapter._parse_result(result)
                app.state.catalog.cached_playbooks = playbooks_str
                logger.info("Successfully fetched and cached playbooks from TriageCore.")
            except Exception as e:
                logger.warning("Failed to fetch and cache playbooks at startup", error=str(e))

            logger.info("Successfully connected to SOC MCP Server and synced tools.")
            break
        except Exception as e:
            # Clean up the stack of this failed attempt
            await app.state.mcp_stack.aclose()
            logger.warning("Failed to connect to SOC MCP server, retrying...", attempt=attempt, max_retries=max_retries, error=str(e))
            if attempt == max_retries:
                logger.error("Failed to connect to SOC MCP server after maximum retries", error=str(e))
                app.state.triage_core_session = None
            else:
                await asyncio.sleep(retry_delay)

    # 3. Share catalog with background triage workflows
    try:
        from agentix.core.triage_workflow import set_shared_catalog
        set_shared_catalog(app.state.catalog)
    except Exception as e:
        logger.error("Failed to share catalog with triage workflows", error=str(e))

    # 3. Start periodic workspace cleanup background task
    if settings.agentix_session_cleanup_on_expire:
        app.state.cleanup_task = asyncio.create_task(
            run_periodic_cleanup(interval_seconds=3600)
        )
        logger.info("Session workspace cleanup task started.")
    else:
        app.state.cleanup_task = None
        
@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Shutting down Agentix Service and closing connections...")
    # Cancel cleanup task
    cleanup_task = getattr(app.state, "cleanup_task", None)
    if cleanup_task and not cleanup_task.done():
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass
    if hasattr(app.state, "mcp_stack"):
        await app.state.mcp_stack.aclose()
    if hasattr(app.state, "redis_store"):
        await app.state.redis_store.close()
    if hasattr(app.state, "pref_store"):
        await app.state.pref_store.close()
    if hasattr(app.state, "deduplicator"):
        await app.state.deduplicator.aclose()
    await postgres_session_repo.close()

# --- Request Models ---

class StreamRequest(BaseModel):
    session_id: str
    message: str
    agent: str | None = None  # Optional agent name (e.g. 'researcher')

class CreateSessionRequest(BaseModel):
    user_id: str = "anonymous"

class SessionResponse(BaseModel):
    session_id: str
    message: str
    workspace_enabled: bool = False


# --- Endpoints ---

app.include_router(webhooks.router)

@app.post("/v1/session", response_model=SessionResponse)
async def create_session(
    req: CreateSessionRequest | None = None,
    redis_store: RedisSessionStore = Depends(get_redis_store)
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
        logger.error("session.postgres_creation_failed", session_id=new_uuid, error=str(e))
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

@app.post("/v1/chat/stream")
async def chat_stream(
    req: StreamRequest,
    redis_store: RedisSessionStore = Depends(get_redis_store),
    catalog: ToolCatalog = Depends(get_catalog),
    pref_store: RedisPreferenceStore = Depends(get_pref_store)
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

    async def _stream_generator():
        # 1. Initialize Orchestrator based on requested agent
        if req.agent:
            try:
                from agentix.agents.factory import AgentFactory
                orchestrator = AgentFactory.create(
                    agent_name=req.agent.lower(),
                    catalog=catalog,
                    memory=redis_store,
                )
                # Inject preference store if possible
                orchestrator._preference_store = pref_store
            except Exception as e:
                logger.error("api.agent_loading_failed", agent=req.agent, error=str(e))
                # Fallback to generic if agent not found
                orchestrator = Orchestrator(
                    catalog=catalog,
                    memory=redis_store,
                    preference_store=pref_store
                )
        else:
            try:
                from agentix.agents.factory import AgentFactory
                orchestrator = await AgentFactory.create_auto(
                    message=req.message,
                    catalog=catalog,
                    memory=redis_store,
                )
                orchestrator._preference_store = pref_store
            except Exception as e:
                logger.error("api.auto_agent_failed", error=str(e))
                # Fallback to generic if auto-routing crashes
                orchestrator = Orchestrator(
                    catalog=catalog,
                    memory=redis_store,
                    preference_store=pref_store
                )
        
        try:
            # Consume the async generator from the orchestrator
            async for step in orchestrator.run_stream(
                session_id=req.session_id,
                user_message=req.message
            ):
                # Convert ReActStep to dictionary then to JSON string
                step_dict = {
                    "type": step.step_type.value,
                    "content": step.content,
                    "tool": step.tool_name,
                    "tool_input": step.tool_input,
                    "tool_output": step.tool_output,
                }
                
                # yield SSE payload format
                # The SSE format is strictly `data: {payload}\n\n`
                json_data = json.dumps(step_dict, default=str)
                yield f"data: {json_data}\n\n"
                
                # Yield context back to event loop briefly
                await asyncio.sleep(0.01)
                
        except Exception as e:
            logger.exception("orchestrator.stream.error")
            err_payload = json.dumps({"error": str(e)})
            yield f"data: {err_payload}\n\n"
            
        yield "data: [DONE]\n\n"

    return StreamingResponse(
        _stream_generator(),
        media_type="text/event-stream"
    )


@app.delete("/v1/session/{session_id}")
async def destroy_session(
    session_id: str,
    redis_store: RedisSessionStore = Depends(get_redis_store)
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


@app.get("/v1/session/{session_id}/workspace")
async def get_workspace_info(
    session_id: str,
    redis_store: RedisSessionStore = Depends(get_redis_store)
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


@app.get("/v1/session/{session_id}/owner")
async def get_session_owner(
    session_id: str,
    redis_store: RedisSessionStore = Depends(get_redis_store)
):
    """
    Return the owner_id for a given session.
    Used by the Gateway to verify session ownership (IDOR prevention).
    """
    if not await redis_store.exists(session_id):
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")

    owner_id = await redis_store.get_metadata(session_id, "owner_id")
    return {"session_id": session_id, "owner_id": owner_id or "anonymous"}


@app.get("/v1/playbooks")
async def get_cached_playbooks(catalog: ToolCatalog = Depends(get_catalog)) -> dict[str, str]:
    """
    Return the cached playbooks markdown text from TriageCore.
    """
    return {"playbooks_markdown": getattr(catalog, "cached_playbooks", "")}


# --- Sessions Persistance Endpoints ---

class UpdateSessionRequest(BaseModel):
    status: str | None = None
    verdict: str | None = None

@app.get("/v1/sessions")
async def list_sessions(
    source: str | None = None,
    status: str | None = None,
    owner_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
):
    try:
        return await postgres_session_repo.list_sessions(
            source=source,
            status=status,
            owner_id=owner_id,
            limit=limit,
            offset=offset,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/v1/sessions/stats")
async def get_session_stats():
    try:
        return await postgres_session_repo.get_session_stats()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/v1/sessions/{session_id}")
async def get_session(session_id: str):
    try:
        session = await postgres_session_repo.get_session(session_id)
        if not session:
            raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")
        return session
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.patch("/v1/sessions/{session_id}")
async def update_session(session_id: str, req: UpdateSessionRequest):
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
                content=f"Session status updated to {req.status.upper()}" + (f" with verdict {verdict_val}" if verdict_val else ""),
            )
            
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/v1/sessions/{session_id}/events")
async def get_session_events(session_id: str, limit: int = 100):
    try:
        session = await postgres_session_repo.get_session(session_id)
        if not session:
            raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")
        return await postgres_session_repo.get_events(session_id, limit=limit)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

