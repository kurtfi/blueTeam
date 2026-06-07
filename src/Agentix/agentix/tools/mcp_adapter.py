"""
MCP Adapter — bridging FastMCP tools with the Agentix Orchestrator.

Features
--------
- Wraps any MCP tool exposed by a FastMCP client into a BaseTool-compatible
  interface so the Orchestrator and ToolCatalog can work with it transparently.
- interrupt_before / interrupt_after hooks for LangGraph-style checkpointing.
- Exponential-backoff retry on transient failures.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any

import structlog
from agentic_common.base_tool import BaseTool, ToolResult

logger = structlog.get_logger(__name__)

_DEFAULT_MAX_RETRIES: int = 3
_DEFAULT_RETRY_DELAY: float = 0.5  # seconds; doubles on each retry


class MCPToolAdapter(BaseTool):
    """
    Wraps an MCP Tool (served by an external FastMCP server) into an Agentix
    BaseTool so the Orchestrator can call it like any other registered tool.

    Interrupt hooks
    ---------------
    ``interrupt_before`` is awaited **before** the remote tool call.
    ``interrupt_after``  is awaited **after** a successful call.
    Both receive the tool name and the current call arguments / result so that
    a LangGraph node (or any caller) can inspect or block execution.

    Retry behaviour
    ---------------
    Transient exceptions trigger an exponential-backoff retry up to
    ``max_retries`` times.  The delay starts at ``retry_delay`` seconds and
    doubles on each attempt.  ``ValueError`` and ``PermissionError`` are
    considered permanent and are **not** retried.
    """

    def __init__(
        self,
        name: str,
        description: str,
        parameters: dict[str, Any],
        client: Any,  # fastmcp.Client
        category: str = "data",
        requires_sandbox: bool = True,
        interrupt_before: Callable[..., Awaitable[None]] | None = None,
        interrupt_after: Callable[..., Awaitable[None]] | None = None,
        max_retries: int = _DEFAULT_MAX_RETRIES,
        retry_delay: float = _DEFAULT_RETRY_DELAY,
    ) -> None:
        self._name = name
        self._description = description
        self._parameters = parameters
        self._client = client
        self.category = category
        self.requires_sandbox = requires_sandbox
        self._interrupt_before = interrupt_before
        self._interrupt_after = interrupt_after
        self._max_retries = max_retries
        self._retry_delay = retry_delay

    # ------------------------------------------------------------------
    # BaseTool property overrides
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:  # type: ignore[override]
        return self._name

    @property
    def description(self) -> str:  # type: ignore[override]
        return self._description

    @property
    def parameters(self) -> dict[str, Any]:  # type: ignore[override]
        return self._parameters

    def requires_confirmation(self, **kwargs: Any) -> bool:
        """
        Check if the tool call requires manual human approval.

        Priority order:
        1. MCP tool metadata field ``x-requires-confirmation`` (dynamic, preferred)
        2. Hardcoded fallback set for well-known destructive tools (backward-compat)
        """
        # 1. Check MCP tool metadata (set in inputSchema extensions)
        schema_extensions = self._parameters.get("x-requires-confirmation")
        if isinstance(schema_extensions, bool):
            return schema_extensions

        # 2. Fallback: well-known destructive tool names
        _DESTRUCTIVE_NAMES = {
            "isolate_endpoint",
            "block_ip",
            "disable_user_account",
            "delete_file",
            "execute_command",
        }
        return self.name in _DESTRUCTIVE_NAMES

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    async def execute(
        self,
        context: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> ToolResult:
        """
        Delegate execution to the FastMCP client with retry and interrupt hooks.

        Args:
            context: Orchestrator context dict (session_id, memory, …).
            **kwargs: Arguments forwarded verbatim to the remote MCP tool.
        """
        log = logger.bind(tool=self.name, attempt=0)

        # --- interrupt_before hook ---
        if self._interrupt_before is not None:
            try:
                await self._interrupt_before(tool_name=self.name, args=kwargs, context=context)
            except Exception as hook_exc:
                log.warning("mcp_adapter.interrupt_before.failed", error=str(hook_exc))

        import tenacity

        # Inject system parameters from orchestrator context into tool arguments
        # if the tool explicitly accepts them in its JSON Schema.
        if context:
            props = self._parameters.get("properties", {})
            if "workspace_path" in props and context.get("workspace_path"):
                kwargs.setdefault("workspace_path", context["workspace_path"])
            if "session_id" in props and context.get("session_id"):
                kwargs.setdefault("session_id", context["session_id"])
            if "user_id" in props and context.get("user_id"):
                kwargs.setdefault("user_id", context["user_id"])

        retryer = tenacity.AsyncRetrying(
            stop=tenacity.stop_after_attempt(self._max_retries + 1),
            wait=tenacity.wait_exponential(multiplier=self._retry_delay, min=self._retry_delay),
            retry=tenacity.retry_if_exception_type(Exception),
            reraise=True,
            before_sleep=lambda rs: logger.warning(
                "mcp_adapter.retrying",
                tool=self.name,
                attempt=rs.attempt_number,
                error=str(rs.outcome.exception()) if rs.outcome else "unknown",
                delay_s=rs.next_action.sleep if rs.next_action else 0,
            ),
        )

        try:
            async for attempt in retryer:
                with attempt:
                    try:
                        logger.info(
                            "mcp_adapter.call_tool",
                            tool=self.name,
                            attempt=attempt.retry_state.attempt_number,
                            arguments=kwargs,
                        )
                        result = await self._client.call_tool(self.name, arguments=kwargs)
                        output = self._parse_result(result)

                        # --- interrupt_after hook ---
                        if self._interrupt_after is not None:
                            try:
                                await self._interrupt_after(
                                    tool_name=self.name, args=kwargs, result=output, context=context
                                )
                            except Exception as hook_exc:
                                logger.warning(
                                    "mcp_adapter.interrupt_after.failed", tool=self.name, error=str(hook_exc)
                                )

                        return ToolResult(success=True, output=output)
                    except (ValueError, PermissionError) as permanent:
                        # Permanent errors — do not retry.
                        logger.error("mcp_adapter.permanent_error", tool=self.name, error=str(permanent))
                        return ToolResult(success=False, error=str(permanent))

        except Exception as exc:
            logger.error("mcp_adapter.max_retries_exceeded", tool=self.name, error=str(exc))
            return ToolResult(
                success=False,
                error=f"Tool '{self.name}' failed after {self._max_retries + 1} attempts: {exc}",
            )

        return ToolResult(success=False, error=f"Tool '{self.name}' failed (unreachable)")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_result(result: Any) -> Any:
        """Normalise the MCP CallToolResult into a Python-native value."""
        output_parts: list[str] = []

        if isinstance(result, list):
            for item in result:
                if hasattr(item, "text"):
                    output_parts.append(item.text)
                elif isinstance(item, dict) and "text" in item:
                    output_parts.append(item["text"])
                else:
                    output_parts.append(str(item))

        elif hasattr(result, "content") and isinstance(result.content, list):
            # MCP SDK standard: CallToolResult(content=[TextContent(type='text', text='...')])
            for item in result.content:
                output_parts.append(item.text if hasattr(item, "text") else str(item))

        else:
            output_parts.append(str(result))

        joined = "\n".join(output_parts)

        # If the tool returned serialised JSON, unwrap it for the Orchestrator.
        try:
            return json.loads(joined)
        except (json.JSONDecodeError, ValueError):
            return joined
