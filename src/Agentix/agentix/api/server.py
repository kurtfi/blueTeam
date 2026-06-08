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
from typing import Any

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
from agentix.core.verdict import parse_verdict
from agentix.registry.catalog import ToolCatalog
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import StreamingResponse
from mcp import ClientSession
from mcp.client.sse import sse_client
from pydantic import BaseModel

logger = structlog.get_logger(__name__)


class SessionTaskManager:
    """
    Manages active agent execution tasks and client subscriber queues.
    This protects agent runs from client disconnects (cancellations).
    """

    def __init__(self) -> None:
        self.tasks: dict[str, asyncio.Task] = {}
        self.queues: dict[str, list[asyncio.Queue]] = {}
        self.lock = asyncio.Lock()

    async def get_or_create_queue(self, session_id: str) -> asyncio.Queue:
        async with self.lock:
            q: asyncio.Queue[Any] = asyncio.Queue()
            if session_id not in self.queues:
                self.queues[session_id] = []
            self.queues[session_id].append(q)
            return q

    async def remove_queue(self, session_id: str, queue: asyncio.Queue) -> None:
        async with self.lock:
            if session_id in self.queues:
                if queue in self.queues[session_id]:
                    self.queues[session_id].remove(queue)
                if not self.queues[session_id]:
                    del self.queues[session_id]

    async def publish_step(self, session_id: str, step_data: dict) -> None:
        async with self.lock:
            queues = self.queues.get(session_id, [])
            for q in queues:
                await q.put(step_data)

    async def register_task(self, session_id: str, task: asyncio.Task) -> None:
        async with self.lock:
            self.tasks[session_id] = task

    async def remove_task(self, session_id: str) -> None:
        async with self.lock:
            if session_id in self.tasks:
                del self.tasks[session_id]

    async def is_running(self, session_id: str) -> bool:
        async with self.lock:
            task = self.tasks.get(session_id)
            if task and not task.done():
                return True
            return False


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
        logger.critical("Failed to run database migrations", error=str(e), alert=True, db_failure=True)

    app.state.task_manager = SessionTaskManager()
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
            app.state.triage_core_session = await app.state.mcp_stack.enter_async_context(
                ClientSession(soc_read, soc_write)
            )
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
            logger.warning(
                "Failed to connect to SOC MCP server, retrying...",
                attempt=attempt,
                max_retries=max_retries,
                error=str(e),
            )
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
        app.state.cleanup_task = asyncio.create_task(run_periodic_cleanup(interval_seconds=3600))
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


async def start_session_background_run(
    session_id: str,
    message: str,
    agent: str | None,
    redis_store: RedisSessionStore,
    catalog: ToolCatalog,
    pref_store: RedisPreferenceStore,
) -> bool:
    """
    Acquires the session lock and spawns a background asyncio task to execute the agent.
    Returns True if the run was started, False if it was already running or locked.
    """
    task_manager = app.state.task_manager

    # 1. Double check task manager status
    if await task_manager.is_running(session_id):
        return False

    # 2. Acquire Redis concurrency lock
    if not await redis_store.acquire_lock(session_id, expire_seconds=120):
        return False

    # Define background worker
    async def background_worker():
        try:
            # Initialize Orchestrator based on requested agent
            active_agent = agent
            if active_agent:
                try:
                    from agentix.agents.factory import AgentFactory

                    orchestrator = AgentFactory.create(
                        agent_name=active_agent.lower(),
                        catalog=catalog,
                        memory=redis_store,
                    )
                    orchestrator._preference_store = pref_store
                except Exception as e:
                    logger.error("api.agent_loading_failed", agent=active_agent, error=str(e))
                    orchestrator = Orchestrator(catalog=catalog, memory=redis_store, preference_store=pref_store)
            else:
                try:
                    from agentix.agents.factory import AgentFactory

                    orchestrator = await AgentFactory.create_auto(
                        message=message,
                        catalog=catalog,
                        memory=redis_store,
                    )
                    orchestrator._preference_store = pref_store
                except Exception as e:
                    logger.error("api.auto_agent_failed", error=str(e))
                    orchestrator = Orchestrator(catalog=catalog, memory=redis_store, preference_store=pref_store)

            from agentix.core.react import StepType

            final_answer = None
            has_confirm = False

            # Consume the async generator from the orchestrator
            async for step in orchestrator.run_stream(session_id=session_id, user_message=message):
                if step.step_type == StepType.CONFIRM:
                    has_confirm = True
                if step.step_type == StepType.ANSWER:
                    final_answer = step.content

                # Convert ReActStep to dictionary
                step_dict = {
                    "type": step.step_type.value,
                    "content": step.content,
                    "tool": step.tool_name,
                    "tool_input": step.tool_input,
                    "tool_output": step.tool_output,
                }

                # Publish to all clients
                await task_manager.publish_step(session_id, step_dict)

                # Persist event in PostgreSQL
                try:
                    event_type = step.step_type.value
                    actor = "agent" if step.step_type in (StepType.THINK, StepType.ACT, StepType.ANSWER) else "system"
                    if step.step_type == StepType.CONFIRM:
                        event_type = "hitl_request"
                        actor = "agent"
                        has_confirm = True
                    elif step.step_type == StepType.OBSERVE:
                        actor = "system" if "Teams Integration" in (step.content or "") else "tool"

                    await postgres_session_repo.add_event(
                        session_id=session_id,
                        event_type=event_type,
                        actor=actor,
                        content=step.content,
                        metadata={
                            "tool_name": step.tool_name,
                            "tool_input": step.tool_input,
                            "tool_output": step.tool_output,
                        },
                    )
                except Exception as ex:
                    logger.critical(
                        "api.event_log_failed", session_id=session_id, error=str(ex), alert=True, db_failure=True
                    )

            # If the stream finished and we have no pending confirmation, mark COMPLETED (only for SIEM/automated sessions)
            if not has_confirm:
                try:
                    session = await postgres_session_repo.get_session(session_id)
                    session_source = session.get("source") if session else "USER"
                except Exception as db_err:
                    logger.critical(
                        "api.fetch_session_source_failed",
                        session_id=session_id,
                        error=str(db_err),
                        alert=True,
                        db_failure=True,
                    )
                    session_source = "USER"  # Default safely to USER

                if session_source != "USER":
                    verdict = parse_verdict(final_answer)
                    await postgres_session_repo.update_status(
                        session_id=session_id,
                        status="COMPLETED",
                        verdict=verdict,
                    )
                    await postgres_session_repo.add_event(
                        session_id=session_id,
                        event_type="status_change",
                        actor="system",
                        content=f"Session status updated to COMPLETED with verdict {verdict}",
                    )
        except Exception as e:
            logger.exception("orchestrator.background.error", session_id=session_id)
            await task_manager.publish_step(session_id, {"error": str(e)})
        finally:
            # Release lock
            await redis_store.release_lock(session_id)
            # Unregister task from manager
            await task_manager.remove_task(session_id)
            # Signal EOF to all clients
            await task_manager.publish_step(session_id, {"type": "EOF"})

    # Spawn background task
    task = asyncio.create_task(background_worker())
    await task_manager.register_task(session_id, task)
    return True


@app.post("/v1/chat/stream")
async def chat_stream(
    req: StreamRequest,
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
    task_manager = app.state.task_manager

    # Get or create subscriber queue for this client connection
    client_queue = await task_manager.get_or_create_queue(session_id)

    # Check if a task is already running for this session.
    # If not running, start it.
    is_running = await task_manager.is_running(session_id)
    if not is_running:
        started = await start_session_background_run(
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


@app.post("/v1/sessions/{session_id}/approve")
async def approve_session(
    session_id: str,
    redis_store: RedisSessionStore = Depends(get_redis_store),
    catalog: ToolCatalog = Depends(get_catalog),
    pref_store: RedisPreferenceStore = Depends(get_pref_store),
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

    started = await start_session_background_run(
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


@app.post("/v1/sessions/{session_id}/reject")
async def reject_session(
    session_id: str,
    redis_store: RedisSessionStore = Depends(get_redis_store),
    catalog: ToolCatalog = Depends(get_catalog),
    pref_store: RedisPreferenceStore = Depends(get_pref_store),
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

    started = await start_session_background_run(
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


@app.delete("/v1/session/{session_id}")
async def destroy_session(session_id: str, redis_store: RedisSessionStore = Depends(get_redis_store)):
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
async def get_workspace_info(session_id: str, redis_store: RedisSessionStore = Depends(get_redis_store)):
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
async def get_session_owner(session_id: str, redis_store: RedisSessionStore = Depends(get_redis_store)):
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
    response: Response,
    source: str | None = None,
    status: str | None = None,
    owner_id: str | None = None,
    search: str | None = None,
    limit: int = 50,
    offset: int = 0,
):
    try:
        total = await postgres_session_repo.count_sessions(
            source=source,
            status=status,
            owner_id=owner_id,
            search=search,
        )
        response.headers["X-Total-Count"] = str(total)
        return await postgres_session_repo.list_sessions(
            source=source,
            status=status,
            owner_id=owner_id,
            search=search,
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
                content=f"Session status updated to {req.status.upper()}"
                + (f" with verdict {verdict_val}" if verdict_val else ""),
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
