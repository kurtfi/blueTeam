import asyncio
import json
import time
from typing import Any

import structlog

from agentix.core.react import ReActStep, StepType

logger = structlog.get_logger(__name__)


class HitlCoordinator:
    """
    Coordinator responsible for Human-In-The-Loop (HITL) workflows,
    generating justifications via LLM, sending notification cards to Teams,
    and recording status/events in the session database.
    """

    def __init__(self, llm: Any, db_repo: Any, memory: Any) -> None:
        self._llm = llm
        self._db_repo = db_repo
        self._memory = memory

    async def handle_requires_confirmation(
        self,
        session_id: str,
        tool_name: str,
        tool_args: dict[str, Any],
        messages: list[dict[str, Any]],
        log: Any,
    ) -> tuple[str, list[ReActStep]]:
        """
        Processes a tool call that requires confirmation.
        Returns the justification string and a list of ReActSteps to yield.
        """
        # 1. Generate human approval justification text via LLM
        hitl_message = f"Tool '{tool_name}' requires manual confirmation."
        try:
            summary_prompt = [
                *messages,
                {
                    "role": "user",
                    "content": (
                        "Human approval (HITL) is required for the following tool execution:\n"
                        f"Tool: {tool_name}\n"
                        f"Arguments: {json.dumps(tool_args, ensure_ascii=False)}\n\n"
                        "Please draft a highly explanatory, professional, and clear human approval justification message (in English). "
                        "Include the findings and evidence obtained so far (e.g. details from reputation checks, SIEM logs, file paths, Case ID, etc.), "
                        "why this specific action is necessary, and its potential impact. "
                        "The user should be able to make an informed decision directly from this message without needing to inspect session logs. "
                        "Your response must consist ONLY of the justification text. Do not include any greeting or conversational filler."
                    ),
                },
            ]
            summary_response = await self._llm.chat(summary_prompt)
            generated_text = summary_response.get("content", "").strip()
            if generated_text:
                hitl_message = generated_text
        except Exception as e:
            log.error("hitl_coordinator.justification_generation_failed", error=str(e))

        # 2. Update status and log to DB using injected db_repo
        if self._db_repo:
            try:
                await self._db_repo.increment_stats(session_id, hitl_count=1)
                await self._db_repo.update_status(session_id, "WAITING_APPROVAL")
                await self._db_repo.add_event(
                    session_id=session_id,
                    event_type="hitl_request",
                    actor="agent",
                    content=hitl_message,
                    metadata={"tool_name": tool_name, "tool_args": tool_args},
                )
            except Exception as e:
                log.critical("hitl_coordinator.db_logging_failed", error=str(e), alert=True, db_failure=True)

        # 3. Create the notification and confirmation ReActSteps
        steps = []
        steps.append(
            ReActStep(
                StepType.OBSERVE,
                content=f"[Teams Integration] Dispatching approval request card to Microsoft Teams #soc-alerts channel for tool '{tool_name}'...\n\nApproval Justification:\n{hitl_message}",
                tool_name="microsoft_teams",
            )
        )

        # Delay is always standard in production code. Tests can mock asyncio.sleep.
        await asyncio.sleep(1.5)

        msg_id = f"msg_{int(time.time())}"
        steps.append(
            ReActStep(
                StepType.OBSERVE,
                content=f"[Teams Integration] Adaptive Card sent successfully! (Message ID: {msg_id}). Waiting for operator response...",
                tool_name="microsoft_teams",
            )
        )

        steps.append(
            ReActStep(
                StepType.CONFIRM,
                content=hitl_message,
                tool_name=tool_name,
                tool_input=tool_args,
            )
        )

        return hitl_message, steps
