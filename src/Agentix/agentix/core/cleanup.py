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


async def cleanup_expired_workspaces() -> dict[str, Any]:
    """
    One-shot scan: find and clean expired session workspaces.

    Returns a summary dict with counts and details.
    """
    ttl_hours = settings.agentix_session_ttl_hours
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
            created_str = meta.get("created_at")
            if not created_str:
                continue

            created_at = datetime.fromisoformat(created_str)
            age_hours = (now - created_at).total_seconds() / 3600

            if age_hours < ttl_hours:
                continue

            status = meta.get("status", "active")

            if status == "active":
                # Selective cleanup: keep outputs, delete temp + downloads
                await ws.cleanup()
                cleaned.append(sid)
                logger.info("cleanup.expired_session.cleaned", session_id=sid, age_hours=round(age_hours, 1))

            elif status == "cleaned" and settings.agentix_session_destroy_on_expire:
                # Already cleaned once — now fully destroy if configured
                age_since_cleanup = 0.0
                cleaned_at = meta.get("cleaned_at")
                if cleaned_at:
                    age_since_cleanup = (now - datetime.fromisoformat(cleaned_at)).total_seconds() / 3600

                # Give an additional grace period (equal to TTL) before full destroy
                if age_since_cleanup >= ttl_hours:
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
