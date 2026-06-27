"""
FastAPI Server for the Agentix platform.

Provides UUID-based session initialization and an SSE streaming endpoint
for interacting with the Agentix Orchestrator in real-time.
"""

from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack
from typing import Any

import structlog
from fastapi import FastAPI
from mcp import ClientSession
from mcp.client.sse import sse_client

from agentic_common.memory import postgres_session_repo
from agentic_common.memory.redis_preferences import RedisPreferenceStore
from agentic_common.memory.redis_store import RedisSessionStore
from agentic_common.settings import settings
from agentix.api.internal_auth import InternalApiKeyMiddleware
from agentix.api.routes import chat, playbooks, sessions, webhooks
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
    app.state.start_session_background_run = start_session_background_run
    app.state.catalog = ToolCatalog()
    app.state.redis_store = RedisSessionStore(redis_url=settings.redis_url)
    app.state.pref_store = RedisPreferenceStore(redis_url=settings.redis_url)
    app.state.deduplicator = AlertDeduplicator(redis_url=settings.redis_url, window_seconds=120)
    app.state.mcp_stack = AsyncExitStack()

    # 2. Initialize SOC MCP Server Connection asynchronously in background
    app.state.triage_core_session = None

    async def connect_mcp_background() -> None:
        max_retries = 15
        retry_delay = 5  # seconds
        for attempt in range(1, max_retries + 1):
            try:
                logger.info("Connecting to SOC MCP Server...", attempt=attempt, url=settings.agentix_triage_core_url)
                # Recreate stack for this attempt to ensure clean state
                app.state.mcp_stack = AsyncExitStack()

                soc_transport = await app.state.mcp_stack.enter_async_context(
                    sse_client(settings.agentix_triage_core_url)
                )
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
                    logger.info(
                        "Successfully registered playbooks and mapped soc_analyst and simulation_analyst to DB."
                    )
                except Exception as e:
                    logger.warning("Failed to fetch, cache, and register playbooks JSON at startup", error=str(e))

                # Attack Simulator MCP Server connection is decoupled and handled directly by standalone simulator client.

                logger.info("Successfully connected to SOC MCP Server and synced tools.")
                break
            except asyncio.CancelledError:
                logger.info("SOC MCP Server connection background task was cancelled.")
                raise
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

    app.state.mcp_connect_task = asyncio.create_task(connect_mcp_background())

    # 3. Share catalog with background triage workflows
    try:
        from agentix.core.triage_workflow import set_shared_catalog

        set_shared_catalog(app.state.catalog)
    except Exception as e:
        logger.error("Failed to share catalog with triage workflows", error=str(e))

    # 4. Start periodic workspace cleanup background task
    if settings.agentix_session_cleanup_on_expire:
        app.state.cleanup_task = asyncio.create_task(run_periodic_cleanup(interval_seconds=3600))
        logger.info("Session workspace cleanup task started.")
    else:
        app.state.cleanup_task = None


@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Shutting down Agentix Service and closing connections...")
    # Cancel connection task
    mcp_connect_task = getattr(app.state, "mcp_connect_task", None)
    if mcp_connect_task and not mcp_connect_task.done():
        mcp_connect_task.cancel()
        try:
            await mcp_connect_task
        except asyncio.CancelledError:
            pass

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


# --- Mount Routes ---

app.include_router(webhooks.router)
app.include_router(sessions.router, prefix="/v1")
app.include_router(playbooks.router, prefix="/v1")
app.include_router(chat.router, prefix="/v1")
