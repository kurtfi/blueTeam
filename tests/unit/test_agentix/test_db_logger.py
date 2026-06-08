from unittest.mock import AsyncMock

import pytest

from agentix.core.db_logger import OrchestratorEventLogger
from agentix.core.react import ReActStep, StepType


@pytest.mark.asyncio
async def test_log_user_message():
    db_mock = AsyncMock()
    logger = OrchestratorEventLogger(db_mock)

    await logger.log_user_message("session-123", "hello world")

    db_mock.increment_stats.assert_called_once_with("session-123", message_count=1)
    db_mock.add_event.assert_called_once_with(
        session_id="session-123",
        event_type="message",
        actor="user",
        content="hello world",
    )


@pytest.mark.asyncio
async def test_log_user_message_siem_skip():
    db_mock = AsyncMock()
    logger = OrchestratorEventLogger(db_mock)

    await logger.log_user_message("session-123", "You are an autonomous Tier 1 (T1) SOC Analyst. alert details...")

    db_mock.increment_stats.assert_called_once_with("session-123", message_count=1)
    db_mock.add_event.assert_not_called()


@pytest.mark.asyncio
async def test_log_step_think():
    db_mock = AsyncMock()
    logger = OrchestratorEventLogger(db_mock)

    step = ReActStep(StepType.THINK, "I am thinking")
    await logger.log_step("session-123", step)

    db_mock.add_event.assert_called_once_with(
        session_id="session-123",
        event_type="think",
        actor="agent",
        content="I am thinking",
        metadata={"tool_name": None, "tool_input": None, "tool_output": None},
    )


@pytest.mark.asyncio
async def test_log_step_confirm():
    db_mock = AsyncMock()
    logger = OrchestratorEventLogger(db_mock)

    step = ReActStep(StepType.CONFIRM, "manual confirmation needed", tool_name="isolate_endpoint", tool_input={"agent_id": "007"})
    await logger.log_step("session-123", step)

    db_mock.add_event.assert_called_once_with(
        session_id="session-123",
        event_type="hitl_request",
        actor="agent",
        content="manual confirmation needed",
        metadata={"tool_name": "isolate_endpoint", "tool_input": {"agent_id": "007"}, "tool_output": None},
    )


@pytest.mark.asyncio
async def test_log_step_observe_teams():
    db_mock = AsyncMock()
    logger = OrchestratorEventLogger(db_mock)

    step = ReActStep(StepType.OBSERVE, "Teams Integration Dispatching card...", tool_name="microsoft_teams")
    await logger.log_step("session-123", step)

    db_mock.add_event.assert_called_once_with(
        session_id="session-123",
        event_type="observe",
        actor="system",
        content="Teams Integration Dispatching card...",
        metadata={"tool_name": "microsoft_teams", "tool_input": None, "tool_output": None},
    )


@pytest.mark.asyncio
async def test_log_guardrail_block():
    db_mock = AsyncMock()
    logger = OrchestratorEventLogger(db_mock)

    await logger.log_guardrail_block("session-123", "malicious payload")

    db_mock.add_event.assert_called_once_with(
        session_id="session-123",
        event_type="error",
        actor="system",
        content="Guardrail block: malicious payload",
    )


@pytest.mark.asyncio
async def test_log_hitl_approval():
    db_mock = AsyncMock()
    logger = OrchestratorEventLogger(db_mock)

    await logger.log_hitl_approval("session-123")

    db_mock.update_status.assert_called_once_with("session-123", "ACTIVE")
    db_mock.add_event.assert_called_once_with(
        session_id="session-123",
        event_type="hitl_response",
        actor="user",
        content="User approved the pending tool execution.",
    )


@pytest.mark.asyncio
async def test_log_hitl_rejection():
    db_mock = AsyncMock()
    logger = OrchestratorEventLogger(db_mock)

    await logger.log_hitl_rejection("session-123")

    db_mock.update_status.assert_called_once_with("session-123", "COMPLETED")
    db_mock.add_event.assert_called_once_with(
        session_id="session-123",
        event_type="hitl_response",
        actor="user",
        content="User rejected the pending tool execution. Workflow cancelled.",
    )


@pytest.mark.asyncio
async def test_log_tool_calls_count():
    db_mock = AsyncMock()
    logger = OrchestratorEventLogger(db_mock)

    await logger.log_tool_calls_count("session-123", 5)

    db_mock.increment_stats.assert_called_once_with("session-123", tool_calls=5)


@pytest.mark.asyncio
async def test_log_completion_non_user():
    db_mock = AsyncMock()
    db_mock.get_session.return_value = {"source": "SIEM"}
    logger = OrchestratorEventLogger(db_mock)

    await logger.log_completion("session-123", "VERDICT: TRUE_POSITIVE")

    db_mock.update_status.assert_called_once_with(
        session_id="session-123",
        status="COMPLETED",
        verdict="TRUE_POSITIVE",
    )
    db_mock.add_event.assert_called_once_with(
        session_id="session-123",
        event_type="status_change",
        actor="system",
        content="Session status updated to COMPLETED with verdict TRUE_POSITIVE",
    )


@pytest.mark.asyncio
async def test_log_completion_user():
    db_mock = AsyncMock()
    db_mock.get_session.return_value = {"source": "USER"}
    logger = OrchestratorEventLogger(db_mock)

    await logger.log_completion("session-123", "VERDICT: TRUE_POSITIVE")

    db_mock.update_status.assert_not_called()
    db_mock.add_event.assert_not_called()


@pytest.mark.asyncio
async def test_log_failure():
    db_mock = AsyncMock()
    logger = OrchestratorEventLogger(db_mock)

    await logger.log_failure("session-123", "Unexpected exception")

    db_mock.update_status.assert_called_once_with("session-123", "FAILED")
    db_mock.add_event.assert_called_once_with(
        session_id="session-123",
        event_type="error",
        actor="system",
        content="Workflow failed with error: Unexpected exception",
    )


@pytest.mark.asyncio
async def test_get_session_source():
    db_mock = AsyncMock()
    db_mock.get_session.return_value = {"source": "SIEM"}
    logger = OrchestratorEventLogger(db_mock)

    res = await logger.get_session_source("session-123")
    assert res == "SIEM"


@pytest.mark.asyncio
async def test_update_langfuse_trace_id():
    db_mock = AsyncMock()
    logger = OrchestratorEventLogger(db_mock)

    await logger.update_langfuse_trace_id("session-123", "trace-abc-123")

    db_mock.update_stats.assert_called_once_with("session-123", langfuse_trace_id="trace-abc-123")
