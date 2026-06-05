"""
Tool Execution Telemetry — lightweight observability for every tool call.
"""
from __future__ import annotations

import time
from collections import defaultdict
from collections.abc import Coroutine
from typing import Any

import structlog

from agentic_common.base_tool import ToolResult

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# In-process metrics store (lightweight, no external dependency)
# ---------------------------------------------------------------------------

class _ToolMetrics:
    """Accumulates per-tool counters and latency totals in memory."""

    def __init__(self) -> None:
        self._calls:    dict[str, int]   = defaultdict(int)
        self._errors:   dict[str, int]   = defaultdict(int)
        self._latency:  dict[str, float] = defaultdict(float)  # total seconds

    def record(self, tool_name: str, success: bool, latency_s: float) -> None:
        self._calls[tool_name] += 1
        self._latency[tool_name] += latency_s
        if not success:
            self._errors[tool_name] += 1

    def snapshot(self) -> dict[str, dict[str, Any]]:
        """Return a point-in-time snapshot of all metrics."""
        result: dict[str, dict[str, Any]] = {}
        for name, calls in self._calls.items():
            avg_ms = (self._latency[name] / calls * 1000) if calls else 0.0
            errors = self._errors.get(name, 0)
            result[name] = {
                "calls":        calls,
                "errors":       errors,
                "success_rate": round((calls - errors) / calls, 4) if calls else 1.0,
                "avg_latency_ms": round(avg_ms, 2),
                "total_latency_s": round(self._latency[name], 4),
            }
        return result


# Module-level singleton — one metrics store per process.
tool_metrics = _ToolMetrics()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def track_tool_call(
    tool_name: str,
    coro: Coroutine[Any, Any, ToolResult],
    parent: Any | None = None,
) -> ToolResult:
    """
    Await *coro* while capturing latency, success/failure, and structured logs.
    """
    span = None
    if parent and hasattr(parent, "span"):
        span = parent.span(name=f"tool:{tool_name}")

    start = time.monotonic()
    result: ToolResult | None = None
    try:
        result = await coro
        if span:
            span.end(output=result.output if result.success else result.error)
        return result
    except Exception as exc:
        # Wrap unexpected exceptions so the caller always gets a ToolResult.
        result = ToolResult(success=False, error=str(exc))
        if span:
            span.end(output=str(exc), level="ERROR")
        return result
    finally:
        latency_s = time.monotonic() - start
        success = result.success if result is not None else False

        tool_metrics.record(tool_name, success, latency_s)

        logger.info(
            "tool.call",
            tool=tool_name,
            success=success,
            latency_ms=round(latency_s * 1000, 2),
            error=result.error if result and not success else None,
        )
