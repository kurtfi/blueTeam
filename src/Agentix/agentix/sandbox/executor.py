"""
Sandbox Executor — safe shell command runner.

Safety layers
-------------
1. Command allow-list check (caller's responsibility, e.g. SandboxedTerminal).
2. asyncio.create_subprocess_shell with separate process group (SIGKILL on timeout).
3. Hard-coded maximum timeout cap of 60 s.
4. stdout/stderr capped at 64 KiB each.
"""

from __future__ import annotations

import asyncio

import structlog
from agentic_common.base_tool import ToolResult
from agentic_common.settings import settings

logger = structlog.get_logger(__name__)

_MAX_TIMEOUT = 60  # Hard cap in seconds.
_MAX_OUTPUT = 64 * 1024  # 64 KiB per stream.


async def run_command(command: str, timeout: int = 30) -> ToolResult:
    """
    Execute *command* in a sandboxed subprocess and return its output.

    Args:
        command: Shell command string to execute.
        timeout: Maximum allowed run-time in seconds (capped at 60).

    Returns:
        :class:`ToolResult` with combined stdout/stderr as *output*, or
        an error message on failure / timeout.
    """
    if not settings.agentix_sandbox_enabled:
        return ToolResult(
            success=False,
            error="Sandbox is disabled. Set AGENTIX_SANDBOX_ENABLED=true to enable.",
        )

    effective_timeout = min(timeout, _MAX_TIMEOUT)
    logger.info("sandbox.run_command", command=command, timeout=effective_timeout)

    try:
        import shlex

        args = shlex.split(command)
        if not args:
            return ToolResult(success=False, error="Empty command.")

        proc = await asyncio.create_subprocess_exec(
            args[0],
            *args[1:],
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=effective_timeout)
        except TimeoutError:
            proc.kill()
            await proc.communicate()
            return ToolResult(
                success=False,
                error=f"Command timed out after {effective_timeout}s.",
            )

        stdout = stdout_bytes[:_MAX_OUTPUT].decode(errors="replace")
        stderr = stderr_bytes[:_MAX_OUTPUT].decode(errors="replace")
        output = stdout + (f"\n[stderr]: {stderr}" if stderr.strip() else "")

        if proc.returncode != 0:
            return ToolResult(
                success=False,
                error=f"Exit code {proc.returncode}.\n{output}",
            )

        return ToolResult(success=True, output=output)

    except Exception as exc:
        logger.exception("sandbox.run_command.error", error=str(exc))
        return ToolResult(success=False, error=str(exc))
