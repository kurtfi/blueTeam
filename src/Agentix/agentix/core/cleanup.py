"""
Workspace Cleanup — background task for expired session workspaces.

Cleanup Strategy
----------------
- Scans all session directories under the workspace root.
- Reads ``.session_meta.json`` to determine age and status.
- Sessions older than ``agentix_session_ttl_hours`` are cleaned:
    - ``temp/`` and ``downloads/`` are **deleted**.
    - ``outputs/`` is **preserved**.
- Full destroy only happens if ``agentix_session_destroy_on_expire`` is enabled.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

import structlog

from agentic_common.settings import settings
from agentic_common.workspace import SessionWorkspace

logger = structlog.get_logger(__name__)


class WorkspaceExpiryPolicy:
    """
    Evaluates workspace metadata to determine if cleanup action is needed.
    Isolates policy evaluation from file system side-effects (SRP).
    """

    def __init__(self, ttl_hours: float, destroy_enabled: bool) -> None:
        self.ttl_hours = ttl_hours
        self.destroy_enabled = destroy_enabled

    def evaluate(self, meta: dict, now: datetime) -> str:
        """
        Returns one of: 'IGNORE', 'CLEAN', 'DESTROY'.
        """
        created_str = meta.get("created_at")
        if not created_str:
            return "IGNORE"

        created_at = datetime.fromisoformat(created_str)
        age_hours = (now - created_at).total_seconds() / 3600

        if age_hours < self.ttl_hours:
            return "IGNORE"

        status = meta.get("status", "active")

        if status == "active":
            return "CLEAN"

        if status == "cleaned" and self.destroy_enabled:
            cleaned_at = meta.get("cleaned_at")
            age_since_cleanup = 0.0
            if cleaned_at:
                age_since_cleanup = (now - datetime.fromisoformat(cleaned_at)).total_seconds() / 3600

            if age_since_cleanup >= self.ttl_hours:
                return "DESTROY"

        return "IGNORE"


async def cleanup_expired_workspaces() -> dict[str, Any]:
    """
    One-shot scan: find and clean expired session workspaces.

    Returns a summary dict with counts and details.
    """
    ttl_hours = settings.agentix_session_ttl_hours
    destroy_enabled = settings.agentix_session_destroy_on_expire
    policy = WorkspaceExpiryPolicy(ttl_hours, destroy_enabled)
    now = datetime.now(UTC)
    session_ids = SessionWorkspace.list_sessions()

    cleaned: list[str] = []
    destroyed: list[str] = []
    errors: list[dict[str, str]] = []

    for sid in session_ids:
        try:
            ws = SessionWorkspace.from_session_id(sid)
            if ws is None:
                continue

            meta = ws.get_metadata()
            action = policy.evaluate(meta, now)

            if action == "CLEAN":
                # Selective cleanup: keep outputs, delete temp + downloads
                await ws.cleanup()
                cleaned.append(sid)
                created_str = meta.get("created_at")
                if created_str:
                    created_at = datetime.fromisoformat(created_str)
                    age_hours = (now - created_at).total_seconds() / 3600
                    logger.info("cleanup.expired_session.cleaned", session_id=sid, age_hours=round(age_hours, 1))

            elif action == "DESTROY":
                # Already cleaned once — now fully destroy if configured
                await ws.destroy()
                destroyed.append(sid)
                logger.info("cleanup.expired_session.destroyed", session_id=sid)

        except Exception as exc:
            errors.append({"session_id": sid, "error": str(exc)})
            logger.error("cleanup.error", session_id=sid, error=str(exc))

    summary = {
        "total_scanned": len(session_ids),
        "cleaned": len(cleaned),
        "destroyed": len(destroyed),
        "errors": len(errors),
        "cleaned_sessions": cleaned,
        "destroyed_sessions": destroyed,
        "error_details": errors,
    }
    logger.info("cleanup.completed", **{k: v for k, v in summary.items() if k != "error_details"})
    return summary


async def run_periodic_cleanup(interval_seconds: int = 3600) -> None:
    """
    Background coroutine that runs cleanup on a fixed interval.

    Designed to be launched via ``asyncio.create_task()`` at application startup.

    Args:
        interval_seconds: Sleep duration between cleanup cycles (default 1 hour).
    """
    logger.info("cleanup.periodic.started", interval_s=interval_seconds)
    while True:
        try:
            await cleanup_expired_workspaces()
        except Exception as exc:
            logger.error("cleanup.periodic.error", error=str(exc))
        await asyncio.sleep(interval_seconds)
