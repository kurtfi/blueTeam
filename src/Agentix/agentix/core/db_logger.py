from __future__ import annotations

from typing import Any

import structlog

from agentix.core.react import ReActStep, StepType
from agentix.core.verdict import parse_verdict

logger = structlog.get_logger(__name__)


class OrchestratorEventLogger:
    """
    Cohesive logger class that encapsulates all PostgreSQL database event
    logging, stats counting, and session status/verdict management.
    """

    def __init__(self, db_repo: Any) -> None:
        self._db_repo = db_repo

    async def log_user_message(self, session_id: str, message: str) -> None:
        if not self._db_repo:
            return
        try:
            await self._db_repo.increment_stats(session_id, message_count=1)
            # Avoid duplicate logs for automated siem triage prompt
            if not message.strip().startswith("You are an autonomous Tier 1 (T1) SOC Analyst."):
                await self._db_repo.add_event(
                    session_id=session_id,
                    event_type="message",
                    actor="user",
                    content=message,
                )
        except Exception as e:
            logger.critical(
                "db_logger.log_user_message_failed",
                session_id=session_id,
                error=str(e),
                alert=True,
                db_failure=True,
            )

    async def log_step(self, session_id: str, step: ReActStep) -> None:
        if not self._db_repo:
            return
        try:
            event_type = step.step_type.value
            actor = "agent" if step.step_type in (StepType.THINK, StepType.ACT, StepType.ANSWER) else "system"

            if step.step_type == StepType.CONFIRM:
                event_type = "hitl_request"
                actor = "agent"
            elif step.step_type == StepType.OBSERVE:
                actor = "system" if "Teams Integration" in (step.content or "") else "tool"

            await self._db_repo.add_event(
                session_id=session_id,
                event_type=event_type,
                actor=actor,
                content=step.content,
                metadata={
                    "tool_name": step.tool_name,
                    "tool_input": step.tool_input,
                    "tool_output": step.tool_output,
                },
            )
        except Exception as e:
            logger.critical(
                "db_logger.log_step_failed",
                session_id=session_id,
                error=str(e),
                alert=True,
                db_failure=True,
            )

    async def log_guardrail_block(self, session_id: str, reason: str) -> None:
        if not self._db_repo:
            return
        try:
            await self._db_repo.add_event(
                session_id=session_id,
                event_type="error",
                actor="system",
                content=f"Guardrail block: {reason}",
            )
        except Exception as e:
            logger.critical(
                "db_logger.log_guardrail_block_failed",
                session_id=session_id,
                error=str(e),
                alert=True,
                db_failure=True,
            )

    async def log_hitl_approval(self, session_id: str) -> None:
        if not self._db_repo:
            return
        try:
            await self._db_repo.update_status(session_id, "ACTIVE")
            await self._db_repo.add_event(
                session_id=session_id,
                event_type="hitl_response",
                actor="user",
                content="User approved the pending tool execution.",
            )
        except Exception as e:
            logger.critical(
                "db_logger.log_hitl_approval_failed",
                session_id=session_id,
                error=str(e),
                alert=True,
                db_failure=True,
            )

    async def log_hitl_rejection(self, session_id: str) -> None:
        if not self._db_repo:
            return
        try:
            await self._db_repo.update_status(session_id, "COMPLETED")
            await self._db_repo.add_event(
                session_id=session_id,
                event_type="hitl_response",
                actor="user",
                content="User rejected the pending tool execution. Workflow cancelled.",
            )
        except Exception as e:
            logger.critical(
                "db_logger.log_hitl_rejection_failed",
                session_id=session_id,
                error=str(e),
                alert=True,
                db_failure=True,
            )

    async def log_tool_calls_count(self, session_id: str, count: int) -> None:
        if not self._db_repo:
            return
        try:
            await self._db_repo.increment_stats(session_id, tool_calls=count)
        except Exception as e:
            logger.critical(
                "db_logger.log_tool_calls_count_failed",
                session_id=session_id,
                error=str(e),
                alert=True,
                db_failure=True,
            )

    async def log_completion(self, session_id: str, final_answer: str) -> None:
        if not self._db_repo:
            return
        try:
            session_source = await self.get_session_source(session_id)
            if session_source != "USER":
                verdict = parse_verdict(final_answer)
                await self._db_repo.update_status(
                    session_id=session_id,
                    status="COMPLETED",
                    verdict=verdict,
                )
                await self._db_repo.add_event(
                    session_id=session_id,
                    event_type="status_change",
                    actor="system",
                    content=f"Session status updated to COMPLETED with verdict {verdict}",
                )
        except Exception as e:
            logger.critical(
                "db_logger.log_completion_failed",
                session_id=session_id,
                error=str(e),
                alert=True,
                db_failure=True,
            )

    async def log_failure(self, session_id: str, error_msg: str) -> None:
        if not self._db_repo:
            return
        try:
            await self._db_repo.update_status(session_id, "FAILED")
            await self._db_repo.add_event(
                session_id=session_id,
                event_type="error",
                actor="system",
                content=f"Workflow failed with error: {error_msg}",
            )
        except Exception as e:
            logger.critical(
                "db_logger.log_failure_failed",
                session_id=session_id,
                error=str(e),
                alert=True,
                db_failure=True,
            )

    async def get_session_source(self, session_id: str) -> str:
        if not self._db_repo:
            return "USER"
        try:
            session = await self._db_repo.get_session(session_id)
            return str(session.get("source")) if (session and session.get("source")) else "USER"
        except Exception as e:
            logger.critical(
                "db_logger.get_session_source_failed",
                session_id=session_id,
                error=str(e),
                alert=True,
                db_failure=True,
            )
            return "USER"

    async def update_langfuse_trace_id(self, session_id: str, trace_id: str) -> None:
        if not self._db_repo:
            return
        try:
            await self._db_repo.update_stats(session_id, langfuse_trace_id=trace_id)
        except Exception as e:
            logger.critical(
                "db_logger.update_langfuse_trace_id_failed",
                session_id=session_id,
                error=str(e),
                alert=True,
                db_failure=True,
            )
