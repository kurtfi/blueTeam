"""
Orchestrator — central decision engine of the Agentix platform.

Design principles encoded here:
  1. Dynamic Tool Selection  — only intent-matched tools are loaded into
                               each request context, not the whole registry.
  2. Chain of Thought (CoT)  — Think → Act → Observe → Answer loop via
                               the ReAct module.
  3. Stateless Logic /       — business logic is pure; session state is
     Stateful Experience       delegated to MemoryStore.
  4. Safety First            — sandbox & permission checks before every
                               tool execution.
  5. Native RAG              — relevant knowledge is automatically injected
                               into the system prompt before the ReAct loop
                               starts. The LLM never needs to call a RAG tool.
  6. Parallel Tool Calls     — independent tool calls in a single LLM turn
                               are fanned out concurrently via asyncio.gather.
"""
from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncGenerator
from typing import TYPE_CHECKING, Any

import structlog
from agentic_common.base_tool import BaseTool
from agentic_common.memory import postgres_session_repo
from agentic_common.memory.session import SessionStore
from agentic_common.settings import settings
from agentic_common.workspace import SessionWorkspace

from agentix.core.context.manager import ContextManager
from agentix.core.llm import LLMClient
from agentix.core.observability import obs
from agentix.core.rag import ContextEnrichmentService
from agentix.core.react import ReActStep, ReActTrace, StepType
from agentix.core.tool_executor import ToolExecutionEngine
from agentix.core.hitl_coordinator import HitlCoordinator
from agentix.registry.catalog import ToolCatalog
from agentix.core.guardrails.manager import GuardrailManager
from agentix.core.guardrails.base import GuardrailResult

if TYPE_CHECKING:
    from agentix.agents.schema import AgentConfig

logger = structlog.get_logger(__name__)



class Orchestrator:
    """
    The central decision-making engine.

    Responsibilities
    ----------------
    - Inject RAG context into the system prompt before the ReAct loop.
    - Parse the user intent from the incoming request.
    - Ask the ToolCatalog for the relevant tools (dynamic selection).
    - Drive the ReAct loop, fanning out parallel tool calls via asyncio.gather.
    - Store/retrieve session context via SessionStore.

    Usage
    -----
    .. code-block:: python

        orchestrator = Orchestrator()
        result = await orchestrator.run(
            session_id="user-42",
            user_message="List the files in /tmp and summarise them",
        )
        print(result.final_answer)
    """

    def __init__(
        self,
        llm: LLMClient | None = None,
        catalog: ToolCatalog | None = None,
        memory: SessionStore | None = None,
        preference_store: Any | None = None,
        max_iterations: int | None = None,
        rag_top_k: int = 5,
        rag_enabled: bool = True,
        config: AgentConfig | None = None,
        vector_store: Any | None = None,
        db_repo: Any | None = None,
        guardrail_manager: GuardrailManager | None = None,
    ) -> None:
        self._llm = llm or LLMClient()
        self._catalog = catalog or ToolCatalog()
        self._memory = memory or SessionStore()
        self._db_repo = db_repo or postgres_session_repo
        self._preference_store = preference_store
        self._config = config
        self._guardrail_manager = guardrail_manager

        
        # Log agent identity
        identity = config.name if config else "Generic Orchestrator"
        logger.info("orchestrator.initialized", agent=identity)

        # Priority: Config > Argument > Settings
        self._max_iterations = (
            config.max_iterations if config else 
            (max_iterations or settings.agentix_max_iterations)
        )
        self._rag_top_k = rag_top_k
        self._rag_enabled = (
            config.rag_enabled if config else rag_enabled
        )

        # Context Management
        self._context_manager = ContextManager(model=str(self._llm.model))

        # Lazily initialise the vector store singleton (avoids connection at import time).
        self._vector_store: Any | None = vector_store

        # Session workspace — lazily initialised per session.
        self._workspace: SessionWorkspace | None = None

        # Delegate Services
        self._rag = ContextEnrichmentService(
            config=config, 
            vector_store=self._vector_store,
            rag_top_k=self._rag_top_k, 
            rag_enabled=self._rag_enabled
        )
        self._tool_executor = ToolExecutionEngine(
            memory=self._memory,
            preference_store=self._preference_store,
            workspace=self._workspace
        )
        self._hitl_coordinator = HitlCoordinator(
            llm=self._llm,
            db_repo=self._db_repo,
            memory=self._memory,
        )

    async def _run_guardrails(
        self, session_id: str, user_message: str, session_source: str
    ) -> GuardrailResult:
        """
        Executes the guardrails manager pipeline on the incoming user message.
        Conforms to SOLID by dynamically loading default guardrails from the factory
        if no manager was injected, and delegating the execution logic to GuardrailManager.
        """
        manager = self._guardrail_manager
        if manager is None:
            from agentix.core.guardrails.factory import GuardrailFactory
            manager = GuardrailFactory.create_default(self._llm)
            self._guardrail_manager = manager

        return await manager.verify(session_id, user_message, session_source)

    async def _init_session_workspace(self, session_id: str) -> None:
        """Initialise per-session workspace if enabled."""
        if settings.agentix_session_workspace_enabled:
            self._workspace = SessionWorkspace.from_session_id(session_id)
            if self._workspace is None:
                # First interaction for this session — create workspace.
                self._workspace = SessionWorkspace(session_id=session_id)
                await self._workspace.initialize()

    async def _log_user_message_to_db(self, session_id: str, user_message: str, log: Any) -> None:
        """Log user message stats and event to the database if repository is configured."""
        if not self._db_repo:
            return
        try:
            await self._db_repo.increment_stats(session_id, message_count=1)
            # Avoid duplicate logs for automated siem triage prompt
            if not user_message.strip().startswith("You are an autonomous Tier 1 (T1) SOC Analyst."):
                await self._db_repo.add_event(
                    session_id=session_id,
                    event_type="message",
                    actor="user",
                    content=user_message,
                )
        except Exception as e:
            log.critical("orchestrator.postgres_user_msg_log_failed", error=str(e), alert=True, db_failure=True)

    async def _check_session_guardrails(
        self, session_id: str, user_message: str, log: Any
    ) -> tuple[bool, str | None]:
        """
        Verify incoming user message against guardrails.
        Returns a tuple of (passed, refusal_message).
        """
        session_source = "USER"
        if self._db_repo:
            try:
                session = await self._db_repo.get_session(session_id)
                session_source = str(session.get("source")) if (session and session.get("source")) else "USER"
            except Exception as db_err:
                log.critical("orchestrator.fetch_session_source_failed", session_id=session_id, error=str(db_err), alert=True, db_failure=True)

        guardrail_result = await self._run_guardrails(session_id, user_message, session_source)
        if guardrail_result.passed:
            return True, None

        refusal = guardrail_result.refusal_message or "Request blocked by guardrails."
        log.info("orchestrator.guardrail_blocked", reason=guardrail_result.reason)

        if self._db_repo:
            try:
                await self._db_repo.add_event(
                    session_id=session_id,
                    event_type="error",
                    actor="system",
                    content=f"Guardrail block: {guardrail_result.reason}",
                )
            except Exception as db_ex:
                log.critical("orchestrator.postgres_guardrail_log_failed", error=str(db_ex), alert=True, db_failure=True)

        await self._memory.append(session_id, user_message, refusal)
        return False, refusal

    def _is_approval_response(self, user_message: str) -> bool:
        """Check if the user response is affirmative."""
        return user_message.lower().strip() in (
            "yes", "confirm", "evet", "onay", "y", "approve", "ok", "tamam", "go", "proceed"
        )

    async def _handle_hitl_approval(
        self, session_id: str, draft_history: list[dict], log: Any
    ) -> tuple[list[dict], dict[str, BaseTool], list[dict], list[dict]]:
        """Handles Postgres updates and prepares tools/schemas/calls when user approves pending tools."""
        log.info("orchestrator.resume.approved")
        if self._db_repo:
            try:
                await self._db_repo.update_status(session_id, "ACTIVE")
                await self._db_repo.add_event(
                    session_id=session_id,
                    event_type="hitl_response",
                    actor="user",
                    content="User approved the pending tool execution.",
                )
            except Exception as e:
                log.critical("orchestrator.postgres_hitl_approved_log_failed", error=str(e), alert=True, db_failure=True)

        await self._memory.set_metadata(session_id, "draft_history", None)

        all_tools = self._catalog.all_tools()
        tool_map = {t.name: t for t in all_tools}
        tool_schemas = [t.to_openai_schema() for t in all_tools]
        
        last_msg = draft_history[-1] if draft_history else {}
        tool_calls = last_msg.get("tool_calls") or []

        return draft_history, tool_map, tool_schemas, tool_calls

    async def _handle_hitl_rejection(self, session_id: str, user_message: str, log: Any) -> None:
        """Handles Postgres updates and cleans up draft state when user rejects pending tools."""
        log.info("orchestrator.resume.rejected", user_message=user_message)
        if self._db_repo:
            try:
                await self._db_repo.update_status(session_id, "COMPLETED")
                await self._db_repo.add_event(
                    session_id=session_id,
                    event_type="hitl_response",
                    actor="user",
                    content="User rejected the pending tool execution. Workflow cancelled.",
                )
            except Exception as e:
                log.critical("orchestrator.postgres_hitl_rejected_log_failed", error=str(e), alert=True, db_failure=True)

        await self._memory.set_metadata(session_id, "draft_history", None)
        await self._memory.append(session_id, user_message, "Action cancelled by user.")

    async def _setup_orchestrator_context(
        self, user_message: str, user_id: str, history: list[dict], log: Any
    ) -> tuple[list[dict], dict[str, BaseTool], list[dict]] | None:
        """
        Dynamically selects tools, retrieves RAG context, and composes system messages.
        Returns a tuple of (messages, tool_map, tool_schemas), or None if no tools are available.
        """
        category_filter = self._config.tool_filters.categories if self._config else None
        name_filter = self._config.tool_filters.names if self._config else None
        exclude_names = self._config.tool_filters.exclude_names if self._config else None

        matched_tools: list[BaseTool] = await self._catalog.select(
            user_message,
            category_filter=category_filter,
            name_filter=name_filter,
            exclude_names=exclude_names,
            use_semantic_search=False,
        )
        tool_schemas = [t.to_openai_schema() for t in matched_tools]
        tool_map = {t.name: t for t in matched_tools}
        log.debug("tools.selected", count=len(matched_tools), names=list(tool_map.keys()))

        if not matched_tools:
            log.error(
                "orchestrator.no_tools_available",
                hint="MCP tools server may be down or catalog is empty. "
                     "Ensure the MCP server is running before starting the API.",
            )
            return None

        rag_context = await self._rag.retrieve_context(user_message, user_id, log)

        base_prompt = (
            self._config.system_prompt_override 
            if self._config and self._config.system_prompt_override 
            else None
        )
        from agentix.core.prompt_composer import SystemPromptComposer
        composer = SystemPromptComposer(base_prompt)
        system_prompt = composer.compose(
            available_tools=matched_tools,
            playbooks_str=getattr(self._catalog, "cached_playbooks", None),
            rag_context=rag_context,
        )

        messages = [
            {"role": "system", "content": system_prompt},
            *history,
            {"role": "user", "content": user_message},
        ]
        messages = self._context_manager.manage(messages)
        return messages, tool_map, tool_schemas

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self, session_id: str, user_message: str) -> ReActTrace:
        """
        Process a single user message and return the full ReAct trace.

        Args:
            session_id:   Identifier for the ongoing conversation / user.
            user_message: The raw user request.

        Returns:
            A :class:`ReActTrace` containing every step and the final answer.
        """
        trace = ReActTrace(request=user_message)

        async for step in self.run_stream(session_id, user_message):
            trace.add_step(step)
            if step.step_type == StepType.ANSWER:
                trace.final_answer = step.content

        return trace

    async def run_stream(
        self, session_id: str, user_message: str
    ) -> AsyncGenerator[ReActStep, None]:
        """
        Process a single user message and yield the full ReAct trace as a stream.

        Args:
            session_id:   Identifier for the ongoing conversation / user.
            user_message: The raw user request.

        Yields:
            Each :class:`ReActStep` in real-time as the agent thinks and acts.
        """
        log = logger.bind(session_id=session_id)
        log.info("orchestrator.run_stream.start", message=user_message[:120])

        await self._log_user_message_to_db(session_id, user_message, log)
        await self._init_session_workspace(session_id)

        # 1. Load conversation history and metadata from memory.
        history = await self._memory.get_history(session_id)
        metadata = await self._memory.get_metadata(session_id)
        user_id = metadata.get("owner_id", "anonymous")

        # Check if we are resuming from a pending approval/confirmation state
        draft_history = metadata.get("draft_history")
        is_resume = False
        tool_calls: list[Any] = []

        if not draft_history:
            passed, refusal = await self._check_session_guardrails(session_id, user_message, log)
            if not passed:
                yield ReActStep(StepType.ANSWER, refusal or "Request blocked.")
                return

        if draft_history:
            if self._is_approval_response(user_message):
                is_resume = True
                messages, tool_map, tool_schemas, tool_calls = await self._handle_hitl_approval(
                    session_id, draft_history, log
                )
            else:
                await self._handle_hitl_rejection(session_id, user_message, log)
                yield ReActStep(StepType.ANSWER, "Action cancelled by user.")
                return
        else:
            setup_res = await self._setup_orchestrator_context(user_message, user_id, history, log)
            if setup_res is None:
                yield ReActStep(
                    StepType.ANSWER,
                    "⚠️ No tools are currently available. The MCP tools server "
                    "may not be running. Please ensure all infrastructure services "
                    "(MCP server, Redis, Postgres) are started and try again.",
                )
                return
            messages, tool_map, tool_schemas = setup_res

        # 5. Observability — Start Langfuse trace
        trace = obs.trace(
            name="orchestrator.run",
            session_id=session_id,
            user_message=user_message[:120],
            tool_count=len(tool_map)
        )

        if trace and hasattr(trace, "id") and trace.id:
            if self._db_repo:
                try:
                    await self._db_repo.update_stats(session_id, langfuse_trace_id=str(trace.id))
                except Exception as e:
                    log.critical("orchestrator.update_trace_id_failed", error=str(e), alert=True, db_failure=True)

        final_answer = ""
        iterations = 0

        # 6. ReAct loop.
        for _ in range(self._max_iterations):
            iterations += 1
            
            # Resume flow: run pending tool calls directly in first iteration
            if is_resume and tool_calls:
                is_resume = False
                confirmation_hit = False
                async for step in self._process_tool_calls_stream(
                    tool_calls=tool_calls,
                    tool_map=tool_map,
                    session_id=session_id,
                    messages=messages,
                    trace=trace,
                    log=log,
                    force_approved=True,
                ):
                    yield step
                    if step.step_type == StepType.CONFIRM:
                        confirmation_hit = True
                
                if confirmation_hit:
                    return
                continue
            
            gen_name = f"generation_{iterations}"
            generation = trace.generation(name=gen_name, model=self._llm.model, input=messages) if trace else None
            
            response = await self._llm.chat(messages, tools=tool_schemas or None)

            if generation:
                generation.end(output=response)

            # --- Final Answer ---
            if response.get("content") and not response.get("tool_calls"):
                content: str = response["content"]
                if "Final Answer:" in content:
                    answer = content.split("Final Answer:")[-1].strip()
                    final_answer = answer
                    yield ReActStep(StepType.ANSWER, answer)
                    break
                # Model responded without a tool but also without the prefix
                final_answer = content
                yield ReActStep(StepType.ANSWER, content)
                break

            # --- Tool calls ---
            tool_calls = response.get("tool_calls") or []
            if not tool_calls:
                if not final_answer:
                    final_answer = "LLM returned an empty response and no tool calls. Aborting."
                    yield ReActStep(StepType.ANSWER, final_answer)
                    log.warning("orchestrator.llm_empty_response")
                break

            messages.append({"role": "assistant", **response})

            confirmation_hit = False
            async for step in self._process_tool_calls_stream(
                tool_calls=tool_calls,
                tool_map=tool_map,
                session_id=session_id,
                messages=messages,
                trace=trace,
                log=log,
            ):
                yield step
                if step.step_type == StepType.CONFIRM:
                    confirmation_hit = True
            
            if confirmation_hit:
                return

        if not final_answer:
            final_answer = "Max iterations reached without a final answer."
            yield ReActStep(StepType.ANSWER, final_answer)
            log.warning("orchestrator.max_iterations_reached", iterations=iterations)

        # 6. Persist updated history.
        await self._memory.append(session_id, user_message, final_answer)
        log.info("orchestrator.run_stream.done", iterations=iterations)

        # 7. Flush Langfuse traces to ensure they are sent before the request ends.
        await obs.flush()

    async def _process_tool_calls_stream(
        self,
        tool_calls: list[dict],
        tool_map: dict[str, BaseTool],
        session_id: str,
        messages: list[dict],
        trace: Any,
        log: Any,
        force_approved: bool = False,
    ) -> AsyncGenerator[ReActStep, None]:
        # Yield THINK steps for all tool calls.
        think_steps: list[tuple[dict, ReActStep]] = []
        for tc in tool_calls:
            tool_name: str = tc["function"]["name"]
            try:
                tool_args = json.loads(tc["function"]["arguments"])
            except json.JSONDecodeError:
                tool_args = {}
            think_step = ReActStep(
                StepType.THINK,
                f"Calling tool '{tool_name}' with {tool_args}",
                tool_name=tool_name,
                tool_input=tool_args,
            )
            yield think_step
            think_steps.append((tc, think_step))

        # HITL check — any tool requiring confirmation stops the whole batch.
        if not force_approved:
            for tc, _ in think_steps:
                t_name = tc["function"]["name"]
                try:
                    t_args = json.loads(tc["function"]["arguments"])
                except json.JSONDecodeError:
                    t_args = {}
                if tool := tool_map.get(t_name):
                    if tool.requires_confirmation(**t_args) and not t_args.get("approved"):
                        # Save the current messages history as draft state for resumption
                        await self._memory.set_metadata(session_id, "draft_history", messages)
                        
                        hitl_message, steps = await self._hitl_coordinator.handle_requires_confirmation(
                            session_id=session_id,
                            tool_name=t_name,
                            tool_args=t_args,
                            messages=messages,
                            log=log,
                        )
                        for step in steps:
                            yield step
                        log.info("orchestrator.confirmation_required", tool=t_name)
                        return  # Caller must re-submit with approved=True.

        # Fan-out: execute all tool calls in parallel.
        # Increment tool_calls count in Postgres
        if self._db_repo:
            try:
                await self._db_repo.increment_stats(session_id, tool_calls=len(tool_calls))
            except Exception as e:
                log.critical("orchestrator.postgres_increment_tool_calls_failed", error=str(e), alert=True, db_failure=True)

        observation_results = await self._tool_executor.execute_tools_parallel(
            tool_calls=tool_calls,
            tool_map=tool_map,
            session_id=session_id,
            parent=trace,
            workspace=self._workspace,
        )

        # Yield OBSERVE steps and feed results back to the model.
        for tc, result in zip(tool_calls, observation_results):
            t_name = tc["function"]["name"]
            observe_step = ReActStep(
                StepType.OBSERVE,
                content=str(result.output) if result.success else f"ERROR: {result.error}",
                tool_name=t_name,
                tool_output=result.output,
            )
            yield observe_step
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tc["id"],
                    "content": (
                        json.dumps(result.output) if result.success
                        else f"ERROR: {result.error}"
                    ),
                }
            )


