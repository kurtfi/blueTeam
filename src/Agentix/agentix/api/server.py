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
from fastapi import Depends, FastAPI, HTTPException, Request, Response, Path, Query
from fastapi.responses import StreamingResponse
from mcp import ClientSession
from mcp.client.sse import sse_client
from pydantic import BaseModel, Field

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

            # Sync Agents in Database
            try:
                from pathlib import Path
                configs_dir = Path(__file__).parent.parent / "agents" / "configs"
                if configs_dir.exists():
                    for yaml_file in configs_dir.glob("*.yaml"):
                        agent_id = yaml_file.stem
                        rel_path = f"agentix/agents/configs/{yaml_file.name}"
                        await postgres_session_repo.register_agent_in_db(agent_id, rel_path)
                    logger.info("Successfully synced agent configurations to DB.")
                else:
                    logger.warning(f"Configs directory not found for sync: {configs_dir}")
            except Exception as e:
                logger.warning("Failed to sync agent configurations to DB at startup", error=str(e))

            # Sync TriageCore Playbooks into our Catalog
            try:
                result = await app.state.triage_core_session.call_tool("list_playbooks")
                from agentix.tools.mcp_adapter import MCPToolAdapter

                playbooks_str = MCPToolAdapter._parse_result(result)
                app.state.catalog.cached_playbooks = playbooks_str
                logger.info("Successfully fetched and cached playbooks from TriageCore.")
            except Exception as e:
                logger.warning("Failed to fetch and cache playbooks at startup", error=str(e))

            # Sync TriageCore Playbooks JSON into our Catalog & DB
            try:
                json_result = await app.state.triage_core_session.call_tool("list_playbooks_json")
                from agentix.tools.mcp_adapter import MCPToolAdapter

                playbooks_json_str = MCPToolAdapter._parse_result(json_result)
                import json
                if not isinstance(playbooks_json_str, str):
                    playbooks_json_str = json.dumps(playbooks_json_str)
                app.state.catalog.cached_playbooks_json = playbooks_json_str
                logger.info("Successfully fetched and cached playbooks JSON from TriageCore.")

                # Register playbooks and seed default mappings
                playbooks_list = json.loads(playbooks_json_str)
                for pb in playbooks_list:
                    pb_id = pb["id"]
                    file_path = pb.get("file_path") or ""
                    await postgres_session_repo.register_playbook_in_db(pb_id, file_path)
                    # Auto-seed: map 'soc_analyst' and 'simulation_analyst' to all playbooks
                    await postgres_session_repo.map_agent_to_playbook("soc_analyst", pb_id)
                    await postgres_session_repo.map_agent_to_playbook("simulation_analyst", pb_id)
                logger.info("Successfully registered playbooks and mapped soc_analyst and simulation_analyst to DB.")
            except Exception as e:
                logger.warning("Failed to fetch, cache, and register playbooks JSON at startup", error=str(e))

            # Connect and Sync Attack Simulator MCP Server (optional/best effort at startup)
            try:
                logger.info("Connecting to Attack Simulator MCP Server...", url=settings.agentix_attack_simulator_url)
                sim_transport = await app.state.mcp_stack.enter_async_context(sse_client(settings.agentix_attack_simulator_url))
                sim_read, sim_write = sim_transport
                app.state.attack_simulator_session = await app.state.mcp_stack.enter_async_context(
                    ClientSession(sim_read, sim_write)
                )
                await app.state.attack_simulator_session.initialize()
                await app.state.catalog.register_mcp_client(app.state.attack_simulator_session)
                logger.info("Successfully connected to Attack Simulator MCP Server and registered tools.")
            except Exception as e:
                logger.warning(
                    "Failed to connect to Attack Simulator MCP server at startup (Simulator might not be running)",
                    url=settings.agentix_attack_simulator_url,
                    error=str(e),
                )

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

    # Start bulk run status poller task
    app.state.bulk_poller_task = asyncio.create_task(_bulk_run_status_poller())
    logger.info("Bulk run status poller task started.")


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

    # Cancel bulk poller task
    bulk_poller_task = getattr(app.state, "bulk_poller_task", None)
    if bulk_poller_task and not bulk_poller_task.done():
        bulk_poller_task.cancel()
        try:
            await bulk_poller_task
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
    session_id: str = Field(..., max_length=100)
    message: str = Field(..., max_length=1000)
    agent: str | None = Field(None, max_length=255)


class CreateSessionRequest(BaseModel):
    user_id: str = Field("anonymous", max_length=255)


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

            # Consume the async generator from the orchestrator
            async for step in orchestrator.run_stream(session_id=session_id, user_message=message):
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
    session_id: str = Path(..., max_length=100),
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
    session_id: str = Path(..., max_length=100),
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
async def destroy_session(session_id: str = Path(..., max_length=100), redis_store: RedisSessionStore = Depends(get_redis_store)):
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
async def get_workspace_info(session_id: str = Path(..., max_length=100), redis_store: RedisSessionStore = Depends(get_redis_store)):
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
async def get_session_owner(session_id: str = Path(..., max_length=100), redis_store: RedisSessionStore = Depends(get_redis_store)):
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


@app.get("/v1/playbooks/summary")
async def get_cached_playbooks_json(catalog: ToolCatalog = Depends(get_catalog)):
    """
    Return the cached playbooks JSON summary from TriageCore.
    """
    data = getattr(catalog, "cached_playbooks_json", [])
    if isinstance(data, str):
        try:
            return json.loads(data)
        except Exception:
            return []
    return data or []


@app.get("/v1/playbooks/{playbook_id}")
async def get_playbook_details(request: Request, playbook_id: str = Path(..., max_length=255)):
    """
    Call the TriageCore MCP tool 'get_playbook_details' and return the result.
    """
    session = getattr(request.app.state, "triage_core_session", None)
    if not session:
        raise HTTPException(status_code=503, detail="TriageCore MCP session is not connected.")
    try:
        result = await session.call_tool("get_playbook_details", {"playbook_id": playbook_id})
        from agentix.tools.mcp_adapter import MCPToolAdapter

        parsed_result = MCPToolAdapter._parse_result(result)

        if isinstance(parsed_result, dict):
            return parsed_result
        try:
            return json.loads(parsed_result)
        except Exception:
            if isinstance(parsed_result, str) and "not found" in parsed_result.lower():
                raise HTTPException(status_code=404, detail=parsed_result)
            return {"detail": parsed_result}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("api.get_playbook_details_failed", playbook_id=playbook_id, error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


# --- Sessions Persistance Endpoints ---


class UpdateSessionRequest(BaseModel):
    status: str | None = Field(None, max_length=50)
    verdict: str | None = Field(None, max_length=50)


@app.get("/v1/sessions")
async def list_sessions(
    response: Response,
    source: str | None = Query(None, max_length=255),
    status: str | None = Query(None, max_length=255),
    owner_id: str | None = Query(None, max_length=255),
    search: str | None = Query(None, max_length=255),
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


@app.patch("/v1/sessions/{session_id}")
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


@app.get("/v1/sessions/{session_id}/events")
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


# --- Simulation Endpoints ---

@app.get("/v1/simulations/scenarios")
async def get_simulations_scenarios():
    """
    Get all ingested attack simulation scenarios from the database.
    """
    try:
        pool = await postgres_session_repo.get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("SELECT * FROM attack_scenarios ORDER BY name ASC")
            scenarios = []
            for row in rows:
                d = dict(row)
                d["id"] = str(d["id"])
                if d["created_at"]:
                    d["created_at"] = d["created_at"].isoformat()
                scenarios.append(d)
            return scenarios
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/v1/simulations/scenarios/{scenario_id}/events")
async def get_simulation_scenario_events(scenario_id: str = Path(..., max_length=100)):
    """
    Get the event sequence preview for a scenario.
    """
    try:
        sc_uuid = uuid.UUID(scenario_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scenario UUID format")
        
    try:
        pool = await postgres_session_repo.get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT id, sequence_order, correlation_rule, mitre_technique, mitre_tactic 
                FROM attack_events 
                WHERE scenario_id = $1 
                ORDER BY sequence_order ASC
                """,
                sc_uuid
            )
            events = []
            for row in rows:
                d = dict(row)
                d["id"] = str(d["id"])
                events.append(d)
            return events
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/v1/simulations/scenarios/{scenario_id}/activate")
async def activate_simulation_scenario(scenario_id: str = Path(..., max_length=100)):
    """
    Activate a scenario and deactivate all others in a transaction.
    """
    try:
        sc_uuid = uuid.UUID(scenario_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scenario UUID format")
        
    try:
        pool = await postgres_session_repo.get_pool()
        async with pool.acquire() as conn:
            async with conn.transaction():
                # Verify exists
                row = await conn.fetchrow("SELECT id FROM attack_scenarios WHERE id = $1", sc_uuid)
                if not row:
                    raise HTTPException(status_code=404, detail="Scenario not found")
                    
                # 1. Reset all to passive
                await conn.execute("UPDATE attack_scenarios SET status = 'passive'")
                await conn.execute("UPDATE attack_events SET status = 'passive'")
                # 2. Activate target scenario
                await conn.execute("UPDATE attack_scenarios SET status = 'active' WHERE id = $1", sc_uuid)
                # 3. Activate target events
                await conn.execute("UPDATE attack_events SET status = 'active' WHERE scenario_id = $1", sc_uuid)
                
        return {"status": "success", "message": f"Scenario {scenario_id} activated successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/v1/simulations/scenarios/{scenario_id}/run")
async def run_simulation_scenario(
    scenario_id: str = Path(..., max_length=100),
    send_rate_per_sec: float = Query(1.0, ge=0.1, le=10.0),
    strip_labels: bool = Query(False)
):
    """
    Trigger a simulation run for the target scenario.
    """
    try:
        sc_uuid = uuid.UUID(scenario_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scenario UUID format")
        
    try:
        pool = await postgres_session_repo.get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow("SELECT name, total_events FROM attack_scenarios WHERE id = $1", sc_uuid)
            if not row:
                raise HTTPException(status_code=404, detail="Scenario not found")
            scenario_name = row["name"]
            total_events = row["total_events"]
            
        # Trigger using MCP server if connected, or direct background task execution
        delay = 1.0 / send_rate_per_sec
        run_id = None
        
        # Try using connected MCP session
        mcp_triggered = False
        if hasattr(app.state, "attack_simulator_session") and app.state.attack_simulator_session:
            try:
                logger.info("Triggering simulation via MCP client...", name=scenario_name, delay=delay, strip_labels=strip_labels)
                res = await app.state.attack_simulator_session.call_tool(
                    "trigger_attack_simulation", 
                    {"scenario_name": scenario_name, "delay_between_events": delay, "strip_labels": strip_labels}
                )
                from agentix.tools.mcp_adapter import MCPToolAdapter
                res_parsed = MCPToolAdapter._parse_result(res)
                if isinstance(res_parsed, dict):
                    res_json = res_parsed
                else:
                    res_json = json.loads(res_parsed)
                run_id = res_json.get("run_id")
                mcp_triggered = True
                logger.info("Simulation triggered via MCP successfully", run_id=run_id)
            except Exception as e:
                logger.warning("Failed to trigger simulation via MCP client, falling back to direct DB/task launch", error=str(e))
                
        if not mcp_triggered:
            # Fallback: direct launch
            try:
                from attack_simulator.models import db_repo
                from attack_simulator.mcp_server import _run_simulation_task
                
                run_id = await db_repo.create_run(str(sc_uuid), total_events, send_rate_per_sec)
                asyncio.create_task(_run_simulation_task(str(sc_uuid), run_id, delay, strip_labels=strip_labels))
                logger.info("Simulation triggered via direct fallback successfully", run_id=run_id)
            except Exception as e:
                logger.critical("Failed to launch simulation directly", error=str(e))
                raise HTTPException(status_code=500, detail=f"Failed to launch simulation: {str(e)}")
                
        return {"status": "success", "run_id": run_id, "message": "Simulation run triggered"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/v1/simulations/runs")
async def get_simulation_runs(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0)
):
    """
    Get recent simulation runs.
    """
    try:
        pool = await postgres_session_repo.get_pool()
        # Evaluate any active runs in real-time
        try:
            async with pool.acquire() as conn:
                active_rows = await conn.fetch("SELECT id FROM simulation_runs WHERE status = 'RUNNING'")
            if active_rows:
                from attack_simulator.evaluator.playbook_match import evaluate_run
                for r in active_rows:
                    try:
                        await evaluate_run(str(r["id"]))
                    except Exception as eval_err:
                        logger.warning("Failed to evaluate active run in list", run_id=str(r["id"]), error=str(eval_err))
        except Exception as e:
            logger.warning("Failed to auto-evaluate active simulation runs", error=str(e))

        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT r.*, s.name as scenario_name 
                FROM simulation_runs r 
                LEFT JOIN attack_scenarios s ON r.scenario_id = s.id 
                ORDER BY r.created_at DESC LIMIT $1 OFFSET $2
                """,
                limit, offset
            )
            runs = []
            for row in rows:
                d = dict(row)
                d["id"] = str(d["id"])
                if d.get("scenario_id"):
                    d["scenario_id"] = str(d["scenario_id"])
                for t_field in ("started_at", "completed_at", "created_at"):
                    if d.get(t_field):
                        d[t_field] = d[t_field].isoformat()
                runs.append(d)
            return runs
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/v1/simulations/runs/{run_id}/results")
async def get_simulation_run_results(run_id: str = Path(..., max_length=100)):
    """
    Get detailed events/results for a simulation run.
    """
    try:
        run_uuid = uuid.UUID(run_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid run UUID format")
        
    try:
        # Evaluate run first in real-time
        try:
            from attack_simulator.evaluator.playbook_match import evaluate_run
            await evaluate_run(run_id)
        except Exception as e:
            logger.warning("Failed to evaluate run before returning results", run_id=run_id, error=str(e))

        pool = await postgres_session_repo.get_pool()
        async with pool.acquire() as conn:
            # Check run exists
            run_row = await conn.fetchrow(
                """
                SELECT r.*, s.name as scenario_name
                FROM simulation_runs r
                LEFT JOIN attack_scenarios s ON r.scenario_id = s.id
                WHERE r.id = $1
                """,
                run_uuid
            )
            if not run_row:
                raise HTTPException(status_code=404, detail="Simulation run not found")
                
            # Get results
            rows = await conn.fetch(
                """
                SELECT res.*, ev.mitre_technique, ev.mitre_tactic, ev.sequence_order, 
                       COALESCE(ts.alert_payload, ev.wazuh_alert) as wazuh_alert
                FROM simulation_results res
                JOIN attack_events ev ON res.event_id = ev.id
                LEFT JOIN sessions ts ON (CASE WHEN res.session_id IS NOT NULL AND res.session_id <> '' THEN res.session_id::uuid ELSE NULL END) = ts.id
                WHERE res.run_id = $1
                ORDER BY ev.sequence_order ASC
                """,
                run_uuid
            )
            results = []
            for row in rows:
                d = dict(row)
                d["id"] = str(d["id"])
                d["run_id"] = str(d["run_id"])
                d["event_id"] = str(d["event_id"])
                if d.get("created_at"):
                    d["created_at"] = d["created_at"].isoformat()
                if isinstance(d.get("wazuh_alert"), str):
                    try:
                        d["wazuh_alert"] = json.loads(d["wazuh_alert"])
                    except Exception:
                        pass
                results.append(d)
                
            run_dict = dict(run_row)
            run_dict["id"] = str(run_dict["id"])
            if run_dict.get("scenario_id"):
                run_dict["scenario_id"] = str(run_dict["scenario_id"])
            for t_field in ("started_at", "completed_at", "created_at"):
                if run_dict.get(t_field):
                    run_dict[t_field] = run_dict[t_field].isoformat()
                    
            return {
                "run": run_dict,
                "results": results
            }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/v1/simulations/stats")
async def get_simulation_stats():
    """
    Get overall simulation precision metrics.
    """
    try:
        pool = await postgres_session_repo.get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT COUNT(*)::int as total_runs,
                       COALESCE(SUM(matched_playbooks), 0)::int as matched,
                       COALESCE(SUM(mismatched_playbooks), 0)::int as mismatched,
                       COALESCE(SUM(no_playbook), 0)::int as no_playbook
                FROM simulation_runs
                """
            )
            stats = dict(row) if row else {"total_runs": 0, "matched": 0, "mismatched": 0, "no_playbook": 0}
            
            # Calculate precision/accuracy rate
            total_finished = stats["matched"] + stats["mismatched"] + stats["no_playbook"]
            accuracy = (stats["matched"] / total_finished * 100.0) if total_finished > 0 else 0.0
            stats["accuracy_rate"] = round(accuracy, 1)
            return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


async def _bulk_run_status_poller() -> None:
    """
    Background worker that polls for incomplete bulk runs and updates their overall status.
    """
    from attack_simulator.models import db_repo
    from attack_simulator.evaluator.playbook_match import evaluate_run

    while True:
        try:
            pool = await postgres_session_repo.get_pool()
            # Find all active/running bulk runs
            async with pool.acquire() as conn:
                bulk_rows = await conn.fetch("SELECT id, total_scenarios FROM simulation_bulk_runs WHERE status = 'RUNNING'")
            
            for row in bulk_rows:
                bulk_run_id = str(row["id"])
                
                # Get runs for this bulk run
                runs = await db_repo.get_runs_for_bulk(bulk_run_id)
                
                completed_scenarios = 0
                matched_count = 0
                mismatched_count = 0
                nobook_count = 0
                all_done = len(runs) >= row["total_scenarios"]  # All scenarios must be launched
                
                for r in runs:
                    r_id = r["id"]
                    # If the sub-run is still running, trigger an evaluation in real-time
                    if r["status"] == "RUNNING":
                        try:
                            await evaluate_run(r_id)
                            # Re-read run status from DB
                            updated_r = await db_repo.get_run(r_id)
                            if updated_r:
                                r = updated_r
                        except Exception as eval_err:
                            logger.warning("Failed to auto-evaluate sub-run in poller", run_id=r_id, error=str(eval_err))
                    
                    if r["status"] in ("COMPLETED", "FAILED"):
                        completed_scenarios += 1
                        matched_count += r.get("matched_playbooks", 0)
                        mismatched_count += r.get("mismatched_playbooks", 0)
                        nobook_count += r.get("no_playbook", 0)
                    else:
                        all_done = False
                
                # Update stats
                bulk_status = "COMPLETED" if (all_done and len(runs) > 0) else "RUNNING"
                
                await db_repo.update_bulk_run_stats(
                    bulk_run_id=bulk_run_id,
                    status=bulk_status,
                    completed_scenarios=completed_scenarios,
                    matched=matched_count,
                    mismatched=mismatched_count,
                    nobook=nobook_count,
                )
                
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error("bulk_run_status_poller.error", error=str(e))
            
        await asyncio.sleep(5)


async def _run_bulk_simulation_task(
    bulk_run_id: str,
    scenario_ids: list[str],
    send_rate_per_sec: float,
    strip_labels: bool,
) -> None:
    """
    Background executor that runs selected scenarios one by one for a bulk run.
    """
    from attack_simulator.models import db_repo
    from attack_simulator.mcp_server import _run_simulation_task
    import uuid

    delay = 1.0 / send_rate_per_sec

    for sc_id in scenario_ids:
        try:
            pool = await postgres_session_repo.get_pool()
            async with pool.acquire() as conn:
                # Check if bulk run was cancelled by user
                bulk_row = await conn.fetchrow("SELECT status FROM simulation_bulk_runs WHERE id = $1", uuid.UUID(bulk_run_id))
                if bulk_row and bulk_row["status"] in ("CANCELLED", "PARTIALLY_COMPLETED"):
                    logger.info("bulk_run.loop_interrupted_due_to_cancellation", bulk_run_id=bulk_run_id, status=bulk_row["status"])
                    break

                row = await conn.fetchrow("SELECT total_events FROM attack_scenarios WHERE id = $1", uuid.UUID(sc_id))
                if not row:
                    logger.warning("bulk_run.scenario_not_found", scenario_id=sc_id)
                    continue
                total_events = row["total_events"]

            run_id = await db_repo.create_run(
                scenario_id=sc_id,
                total_events=total_events,
                send_rate_per_sec=send_rate_per_sec,
                bulk_run_id=bulk_run_id,
            )

            logger.info("bulk_run.starting_scenario", bulk_run_id=bulk_run_id, scenario_id=sc_id, run_id=run_id)
            # Awaiting the simulation task makes scenario execution sequential
            await _run_simulation_task(
                scenario_id=sc_id,
                run_id=run_id,
                delay_seconds=delay,
                strip_labels=strip_labels,
            )
            logger.info("bulk_run.finished_scenario", bulk_run_id=bulk_run_id, scenario_id=sc_id, run_id=run_id)

            # Short sleep between scenarios to prevent database locks/throttling
            await asyncio.sleep(2)
        except Exception as e:
            logger.exception("bulk_run.scenario_failed", bulk_run_id=bulk_run_id, scenario_id=sc_id, error=str(e))


@app.get("/v1/settings/llm")
async def get_active_llm_setting():
    """
    Get active LLM settings for the core Agentix platform.
    """
    return {
        "provider": settings.agentix_llm_provider,
        "model": (
            settings.openai_model if settings.agentix_llm_provider == "openai"
            else settings.gemini_model if settings.agentix_llm_provider == "gemini"
            else settings.ollama_model
        )
    }


class BulkRunRequest(BaseModel):
    name: str = Field(..., max_length=255)
    scenario_ids: list[str]
    send_rate_per_sec: float = Field(1.0, ge=0.1, le=10.0)
    strip_labels: bool = False


@app.post("/v1/simulations/bulk-runs")
async def trigger_bulk_simulations(payload: BulkRunRequest):
    """
    Triggers a bulk run for selected scenarios.
    """
    if not payload.scenario_ids:
        raise HTTPException(status_code=400, detail="At least one scenario ID must be provided")

    try:
        from attack_simulator.models import db_repo
        
        # 1. Get current LLM model info
        llm_provider = settings.agentix_llm_provider
        llm_model = (
            settings.openai_model if llm_provider == "openai"
            else settings.gemini_model if llm_provider == "gemini"
            else settings.ollama_model
        )
        
        # 2. Create the bulk run record
        bulk_run_id = await db_repo.create_bulk_run(
            name=payload.name,
            llm_provider=llm_provider,
            llm_model=llm_model,
            strip_labels=payload.strip_labels,
            send_rate_per_sec=payload.send_rate_per_sec,
            total_scenarios=len(payload.scenario_ids),
        )
        
        # 3. Trigger sequential background execution
        asyncio.create_task(
            _run_bulk_simulation_task(
                bulk_run_id=bulk_run_id,
                scenario_ids=payload.scenario_ids,
                send_rate_per_sec=payload.send_rate_per_sec,
                strip_labels=payload.strip_labels,
            )
        )
        
        return {
            "status": "success",
            "bulk_run_id": bulk_run_id,
            "message": "Bulk simulation run started in background"
        }
    except Exception as e:
        logger.exception("api.trigger_bulk_simulations.error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/v1/simulations/bulk-runs")
async def list_bulk_runs(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0)
):
    """
    Get recent bulk simulation runs.
    """
    try:
        pool = await postgres_session_repo.get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT * 
                FROM simulation_bulk_runs 
                ORDER BY created_at DESC LIMIT $1 OFFSET $2
                """,
                limit, offset
            )
            bulk_runs = []
            for row in rows:
                d = dict(row)
                d["id"] = str(d["id"])
                for t_field in ("completed_at", "created_at"):
                    if d.get(t_field):
                        d[t_field] = d[t_field].isoformat()
                bulk_runs.append(d)
            return bulk_runs
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/v1/simulations/bulk-runs/{bulk_run_id}/results")
async def get_bulk_run_results(bulk_run_id: str = Path(..., max_length=100)):
    """
    Get detailed results for all scenario runs under a bulk run.
    """
    try:
        bulk_uuid = uuid.UUID(bulk_run_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid bulk run UUID format")

    try:
        from attack_simulator.models import db_repo
        
        # 1. Get bulk run meta
        bulk_meta = await db_repo.get_bulk_run(bulk_run_id)
        if not bulk_meta:
            raise HTTPException(status_code=404, detail="Bulk run not found")
        
        # Format timestamps
        for t_field in ("completed_at", "created_at"):
            if bulk_meta.get(t_field):
                bulk_meta[t_field] = bulk_meta[t_field].isoformat()

        # 2. Get all sub runs
        runs = await db_repo.get_runs_for_bulk(bulk_run_id)
        for r in runs:
            for t_field in ("started_at", "completed_at", "created_at"):
                if r.get(t_field):
                    r[t_field] = r[t_field].isoformat()

        return {
            "bulk_run": bulk_meta,
            "runs": runs
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/v1/simulations/bulk-runs/{bulk_run_id}/cancel")
async def cancel_bulk_run_endpoint(bulk_run_id: str = Path(..., max_length=100)):
    """
    Cancels a bulk run, skipping remaining scenarios.
    """
    try:
        bulk_uuid = uuid.UUID(bulk_run_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid bulk run UUID format")

    try:
        from attack_simulator.models import db_repo
        
        # Check if bulk run exists
        bulk_meta = await db_repo.get_bulk_run(bulk_run_id)
        if not bulk_meta:
            raise HTTPException(status_code=404, detail="Bulk run not found")
        
        if bulk_meta["status"] != "RUNNING":
            raise HTTPException(status_code=400, detail=f"Bulk run is in '{bulk_meta['status']}' state and cannot be cancelled.")
        
        await db_repo.cancel_bulk_run(bulk_run_id)
        
        return {
            "status": "success",
            "message": "Bulk run cancellation processed successfully"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("api.cancel_bulk_run.error", bulk_run_id=bulk_run_id, error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


