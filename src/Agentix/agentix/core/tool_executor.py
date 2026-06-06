"""
Tool Execution Engine for orchestrating parallel tool invocations.
"""
import asyncio
import json
from typing import Any

from agentic_common.base_tool import BaseTool, ToolResult
from agentic_common.telemetry import track_tool_call


class ToolExecutionEngine:
    """
    Engine responsible for handling tool executions in parallel, 
    dealing with timeouts, error handling, and formatting outputs.
    """
    def __init__(self, memory: Any = None, preference_store: Any = None, workspace: Any = None):
        self._memory = memory
        self._preference_store = preference_store
        self._workspace = workspace

    async def execute_tools_parallel(
        self,
        tool_calls: list[dict],
        tool_map: dict[str, BaseTool],
        session_id: str,
        parent: Any | None = None,
        workspace: Any | None = None,
    ) -> list[ToolResult]:
        """
        Execute all tool calls concurrently using asyncio.gather.

        Each tool call is wrapped in ``track_tool_call`` for telemetry.
        Exceptions are captured as failed ToolResults rather than propagating.
        """
        active_workspace = workspace if workspace is not None else self._workspace
        workspace_path = str(active_workspace.root) if active_workspace else None
        
        # Get user_id for tools (from metadata)
        metadata = await self._memory.get_metadata(session_id) if self._memory else {}
        user_id = metadata.get("owner_id", "anonymous")

        context = {
            "session_id": session_id,
            "user_id": user_id,
            "memory": self._memory,
            "preference_store": self._preference_store,
            "workspace": active_workspace,
            "workspace_path": workspace_path,
        }

        async def _single(tc: dict) -> ToolResult:
            tool_name: str = tc["function"]["name"]
            try:
                tool_args = json.loads(tc["function"]["arguments"])
            except json.JSONDecodeError:
                tool_args = {}
            return await self._execute_tool(tool_map, tool_name, tool_args, context, parent)

        results = await asyncio.gather(
            *[_single(tc) for tc in tool_calls],
            return_exceptions=True,
        )

        # Normalise any unexpected exceptions into ToolResult objects.
        normalised: list[ToolResult] = []
        for r in results:
            if isinstance(r, ToolResult):
                normalised.append(r)
            elif isinstance(r, Exception):
                normalised.append(ToolResult(success=False, error=str(r)))
            elif isinstance(r, BaseException):
                # Do not swallow CancelledError or SystemExit
                raise r
            else:
                normalised.append(ToolResult(success=True, output=r))
        return normalised

    async def _execute_tool(
        self,
        tool_map: dict[str, BaseTool],
        tool_name: str,
        tool_args: dict[str, Any],
        context: dict[str, Any],
        parent: Any | None = None,
    ) -> ToolResult:
        tool = tool_map.get(tool_name)
        if tool is None:
            return ToolResult(success=False, error=f"Tool '{tool_name}' not found.")

        return await track_tool_call(
            tool_name,
            tool.execute(context=context, **tool_args),
            parent=parent,
        )
