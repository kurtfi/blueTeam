"""
Orchestrator — central decision engine of the Agentix platform.
"""

from __future__ import annotations

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
from agentix.core.db_logger import OrchestratorEventLogger
from agentix.core.guardrails.manager import GuardrailManager
from agentix.core.hitl_coordinator import HitlCoordinator
from agentix.core.llm import LLMClient
from agentix.core.observability import obs
from agentix.core.rag import ContextEnrichmentService
from agentix.core.react import ReActStep, ReActTrace, StepType
from agentix.core.tool_executor import ToolExecutionEngine
from agentix.registry.catalog import ToolCatalog

if TYPE_CHECKING:
    from agentix.agents.schema import AgentConfig

logger = structlog.get_logger(__name__)


class Orchestrator:
    """
    The central decision-making engine.
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
        self._max_iterations = config.max_iterations if config else (max_iterations or settings.agentix_max_iterations)
        self._rag_top_k = rag_top_k
        self._rag_enabled = config.rag_enabled if config else rag_enabled

        # Context Management
        self._context_manager = ContextManager(model=str(self._llm.model))

        # Lazily initialise the vector store singleton (avoids connection at import time).
        self._vector_store: Any | None = vector_store

        # Session workspace — lazily initialised per session.
        self._workspace: SessionWorkspace | None = None

        # Delegate Services
        self._rag = ContextEnrichmentService(
            config=config, vector_store=self._vector_store, rag_top_k=self._rag_top_k, rag_enabled=self._rag_enabled
        )
        self._tool_executor = ToolExecutionEngine(
            memory=self._memory, preference_store=self._preference_store, workspace=self._workspace
        )
        self._hitl_coordinator = HitlCoordinator(
            llm=self._llm,
            db_repo=self._db_repo,
            memory=self._memory,
        )
        self._db_logger = OrchestratorEventLogger(self._db_repo)

    async def _run_guardrails(self, session_id: str, user_message: str, session_source: str) -> Any:
        """Executes guardrails pipeline on incoming user message."""
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

    async def _check_session_guardrails(self, session_id: str, user_message: str, log: Any) -> tuple[bool, str | None]:
        """Verify incoming user message against guardrails."""
        session_source = await self._db_logger.get_session_source(session_id)

        guardrail_result = await self._run_guardrails(session_id, user_message, session_source)
        if guardrail_result.passed:
            return True, None

        refusal = guardrail_result.refusal_message or "Request blocked by guardrails."
        log.info("orchestrator.guardrail_blocked", reason=guardrail_result.reason)

        await self._db_logger.log_guardrail_block(session_id, guardrail_result.reason)
        await self._memory.append(session_id, user_message, refusal)
        return False, refusal

    def _is_approval_response(self, user_message: str) -> bool:
        """Check if the user response is affirmative."""
        return user_message.lower().strip() in (
            "yes",
            "confirm",
            "evet",
            "onay",
            "y",
            "approve",
            "ok",
            "tamam",
            "go",
            "proceed",
        )

    async def _handle_hitl_approval(
        self, session_id: str, draft_history: list[dict], log: Any
    ) -> tuple[list[dict], dict[str, BaseTool], list[dict], list[dict]]:
        """Prepares tools/schemas/calls when user approves pending tools."""
        log.info("orchestrator.resume.approved")
        await self._db_logger.log_hitl_approval(session_id)
        await self._memory.set_metadata(session_id, "draft_history", None)

        all_tools = self._catalog.all_tools()
        tool_map = {t.name: t for t in all_tools}
        tool_schemas = [t.to_openai_schema() for t in all_tools]

        last_msg = draft_history[-1] if draft_history else {}
        tool_calls = last_msg.get("tool_calls") or []

        return draft_history, tool_map, tool_schemas, tool_calls

    async def _handle_hitl_rejection(self, session_id: str, user_message: str, log: Any) -> None:
        """Cleans up draft state when user rejects pending tools."""
        log.info("orchestrator.resume.rejected", user_message=user_message)
        await self._db_logger.log_hitl_rejection(session_id)
        await self._memory.set_metadata(session_id, "draft_history", None)
        await self._memory.append(session_id, user_message, "Action cancelled by user.")

    async def _setup_orchestrator_context(
        self, user_message: str, user_id: str, history: list[dict], log: Any
    ) -> tuple[list[dict], dict[str, BaseTool], list[dict]] | None:
        """Dynamically selects tools, retrieves RAG context, and composes system messages."""
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
            self._config.system_prompt_override if self._config and self._config.system_prompt_override else None
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

    async def _prepare_session(
        self, session_id: str, user_message: str, log: Any
    ) -> tuple[list[dict], dict, str] | None:
        """Initialise workspace, metadata, and history."""
        await self._db_logger.log_user_message(session_id, user_message)
        await self._init_session_workspace(session_id)

        history = await self._memory.get_history(session_id)
        metadata = await self._memory.get_metadata(session_id)
        user_id = metadata.get("owner_id", "anonymous")

        return history, metadata, user_id

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self, session_id: str, user_message: str) -> ReActTrace:
        """Process a single user message and return the full ReAct trace."""
        trace = ReActTrace(request=user_message)

        async for step in self.run_stream(session_id, user_message):
            trace.add_step(step)
            if step.step_type == StepType.ANSWER:
                trace.final_answer = step.content

        return trace

    async def run_stream(self, session_id: str, user_message: str) -> AsyncGenerator[ReActStep, None]:
        """Process a single user message and yield the full ReAct trace as a stream."""
        log = logger.bind(session_id=session_id)
        log.info("orchestrator.run_stream.start", message=user_message[:120])

        try:
            prep_res = await self._prepare_session(session_id, user_message, log)
            if prep_res is None:
                return
            history, metadata, user_id = prep_res

            # Check if we are resuming from a pending approval/confirmation state
            draft_history = metadata.get("draft_history")
            is_resume = False
            tool_calls: list[Any] = []

            if not draft_history:
                passed, refusal = await self._check_session_guardrails(session_id, user_message, log)
                if not passed:
                    refusal_step = ReActStep(StepType.ANSWER, refusal or "Request blocked.")
                    yield refusal_step
                    await self._db_logger.log_step(session_id, refusal_step)
                    return

            if draft_history:
                if self._is_approval_response(user_message):
                    is_resume = True
                    messages, tool_map, tool_schemas, tool_calls = await self._handle_hitl_approval(
                        session_id, draft_history, log
                    )
                else:
                    await self._handle_hitl_rejection(session_id, user_message, log)
                    rej_step = ReActStep(StepType.ANSWER, "Action cancelled by user.")
                    yield rej_step
                    await self._db_logger.log_step(session_id, rej_step)
                    return
            else:
                setup_res = await self._setup_orchestrator_context(user_message, user_id, history, log)
                if setup_res is None:
                    err_step = ReActStep(
                        StepType.ANSWER,
                        "⚠️ No tools are currently available. The MCP tools server "
                        "may not be running. Please ensure all infrastructure services "
                        "(MCP server, Redis, Postgres) are started and try again.",
                    )
                    yield err_step
                    await self._db_logger.log_step(session_id, err_step)
                    return
                messages, tool_map, tool_schemas = setup_res

            # 5. Observability — Start Langfuse trace
            trace = obs.trace(
                name="orchestrator.run",
                session_id=session_id,
                user_message=user_message[:120],
                tool_count=len(tool_map),
            )

            if trace and hasattr(trace, "id") and trace.id:
                await self._db_logger.update_langfuse_trace_id(session_id, str(trace.id))

            final_answer = ""
            iterations = 0
            confirmation_hit = False

            # 6. ReAct loop.
            for _ in range(self._max_iterations):
                iterations += 1

                # Resume flow: run pending tool calls directly in first iteration
                if is_resume and tool_calls:
                    is_resume = False
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
                        await self._db_logger.log_step(session_id, step)
                        if step.step_type == StepType.CONFIRM:
                            confirmation_hit = True

                    if confirmation_hit:
                        return
                    continue

                gen_name = f"generation_{iterations}"
                generation = trace.generation(name=gen_name, model=self._llm.model, input=messages) if trace else None

                response = await self._llm.chat(messages, tools=tool_schemas or None)  # type: ignore[arg-type]

                if generation:
                    generation.end(output=response)

                # --- Final Answer ---
                if response.get("content") and not response.get("tool_calls"):
                    content: str = response["content"]
                    if "Final Answer:" in content:
                        answer = content.split("Final Answer:")[-1].strip()
                        final_answer = answer
                        ans_step = ReActStep(StepType.ANSWER, answer)
                        yield ans_step
                        await self._db_logger.log_step(session_id, ans_step)
                        break
                    # Model responded without a tool but also without the prefix
                    final_answer = content
                    ans_step = ReActStep(StepType.ANSWER, content)
                    yield ans_step
                    await self._db_logger.log_step(session_id, ans_step)
                    break

                # --- Tool calls ---
                tool_calls = response.get("tool_calls") or []
                if not tool_calls:
                    if not final_answer:
                        final_answer = "LLM returned an empty response and no tool calls. Aborting."
                        ans_step = ReActStep(StepType.ANSWER, final_answer)
                        yield ans_step
                        await self._db_logger.log_step(session_id, ans_step)
                        log.warning("orchestrator.llm_empty_response")
                    break

                messages.append({"role": "assistant", **response})

                async for step in self._process_tool_calls_stream(
                    tool_calls=tool_calls,
                    tool_map=tool_map,
                    session_id=session_id,
                    messages=messages,
                    trace=trace,
                    log=log,
                ):
                    yield step
                    await self._db_logger.log_step(session_id, step)
                    if step.step_type == StepType.CONFIRM:
                        confirmation_hit = True

                if confirmation_hit:
                    return

            if not final_answer and not confirmation_hit:
                final_answer = "Max iterations reached without a final answer."
                ans_step = ReActStep(StepType.ANSWER, final_answer)
                yield ans_step
                await self._db_logger.log_step(session_id, ans_step)
                log.warning("orchestrator.max_iterations_reached", iterations=iterations)

            # Persist updated history & stats.
            if not confirmation_hit:
                await self._memory.append(session_id, user_message, final_answer)
                await self._db_logger.log_completion(session_id, final_answer)

            log.info("orchestrator.run_stream.done", iterations=iterations)

        except Exception as e:
            log.exception("orchestrator.run_stream.failed", error=str(e))
            await self._db_logger.log_failure(session_id, str(e))
            err_step = ReActStep(StepType.ANSWER, f"Error during execution: {str(e)}")
            yield err_step
            await self._db_logger.log_step(session_id, err_step)
            raise e
        finally:
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
        await self._db_logger.log_tool_calls_count(session_id, len(tool_calls))

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
                    "content": (json.dumps(result.output) if result.success else f"ERROR: {result.error}"),
                }
            )
