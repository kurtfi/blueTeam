import sys
from pathlib import Path

# Add src/Agentix and src/AgenticCommon to sys.path
root_dir = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(root_dir / "src" / "Agentix"))
sys.path.insert(0, str(root_dir / "src" / "AgenticCommon"))

from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from agentic_common.memory.redis_store import RedisSessionStore
from agentix.core.react import StepType
from agentix.registry.catalog import ToolCatalog
from agentix.core.orchestrator import Orchestrator

from agentix.core.guardrails.base import BaseGuardrail, GuardrailResult
from agentix.core.guardrails.manager import GuardrailManager
from agentix.core.guardrails.factory import GuardrailFactory
from agentix.core.guardrails.security_topic import SecurityTopicGuardrail
from agentix.core.llm import LLMClient


class DummyPassGuardrail(BaseGuardrail):
    async def validate(self, session_id: str, message: str, session_source: str = "USER") -> GuardrailResult:
        return GuardrailResult(passed=True)


class DummyBlockGuardrail(BaseGuardrail):
    async def validate(self, session_id: str, message: str, session_source: str = "USER") -> GuardrailResult:
        if session_source != "USER":
            return GuardrailResult(passed=True)
        return GuardrailResult(passed=False, reason="Blocked by dummy guardrail", refusal_message="Refused by dummy.")


@pytest.mark.asyncio
async def test_guardrail_manager_execution():
    # 1. Test passing chain
    manager_pass = GuardrailManager([DummyPassGuardrail(), DummyPassGuardrail()])
    res_pass = await manager_pass.verify("session_123", "Hello", "USER")
    assert res_pass.passed is True

    # 2. Test blocking chain
    manager_block = GuardrailManager([DummyPassGuardrail(), DummyBlockGuardrail(), DummyPassGuardrail()])
    res_block = await manager_block.verify("session_123", "Hello", "USER")
    assert res_block.passed is False
    assert res_block.reason == "Blocked by dummy guardrail"
    assert res_block.refusal_message == "Refused by dummy."

    # 3. Test dynamic registration
    manager_dynamic = GuardrailManager()
    manager_dynamic.register(DummyPassGuardrail())
    manager_dynamic.register(DummyBlockGuardrail())
    res_dyn = await manager_dynamic.verify("session_123", "Hello", "USER")
    assert res_dyn.passed is False
    
    # 4. Test bypass when session_source is not USER
    res_bypass = await manager_block.verify("session_123", "Hello", "SIEM")
    assert res_bypass.passed is True


@pytest.mark.asyncio
async def test_security_topic_guardrail_pass():
    mock_llm = AsyncMock(spec=LLMClient)
    mock_llm.chat.return_value = {"content": "PASS"}

    guardrail = SecurityTopicGuardrail(llm=mock_llm)
    res = await guardrail.validate("session_123", "Can you help me block an IP?", "USER")
    
    assert res.passed is True
    mock_llm.chat.assert_called_once()


@pytest.mark.asyncio
async def test_security_topic_guardrail_block():
    mock_llm = AsyncMock(spec=LLMClient)
    mock_llm.chat.return_value = {"content": "BLOCK: Üzgünüm, sadece siber güvenlik konularına cevap verebilirim."}

    guardrail = SecurityTopicGuardrail(llm=mock_llm)
    res = await guardrail.validate("session_123", "Bana çikolatalı pasta tarifi ver.", "USER")
    
    assert res.passed is False
    assert res.reason == "Out-of-scope query"
    assert res.refusal_message == "Üzgünüm, sadece siber güvenlik konularına cevap verebilirim."
    mock_llm.chat.assert_called_once()


@pytest.mark.asyncio
async def test_orchestrator_integration_blocks_and_logs():
    # Setup mock memory and DB repo
    mock_memory = AsyncMock(spec=RedisSessionStore)
    mock_memory.get_history.return_value = []
    mock_memory.get_metadata.return_value = {}

    mock_db = AsyncMock()
    mock_db.get_session.return_value = {"source": "USER"}
    mock_llm = AsyncMock(spec=LLMClient)
    mock_llm.model = "test-model"

    catalog = ToolCatalog()
    
    # Instantiate orchestrator with a GuardrailManager containing a DummyBlockGuardrail
    orchestrator = Orchestrator(
        llm=mock_llm,
        catalog=catalog,
        memory=mock_memory,
        db_repo=mock_db,
        max_iterations=5,
        rag_enabled=False,
        guardrail_manager=GuardrailManager([DummyBlockGuardrail()])
    )

    steps = []
    async for step in orchestrator.run_stream("session_123", "Bana çikolatalı pasta tarifi ver."):
        steps.append(step)

    # 1. Main LLM chat should NOT be called since the query is blocked before reasoning starts
    mock_llm.chat.assert_not_called()

    # 2. ReActStep answer should match the refusal message
    assert len(steps) == 1
    assert steps[0].step_type == StepType.ANSWER
    assert steps[0].content == "Refused by dummy."

    # 3. Guardrail error block event should be logged in DB
    mock_db.add_event.assert_any_call(
        session_id="session_123",
        event_type="error",
        actor="system",
        content="Guardrail block: Blocked by dummy guardrail"
    )

    # 4. Refusal answer must be appended to the conversation history in memory
    mock_memory.append.assert_called_once_with(
        "session_123",
        "Bana çikolatalı pasta tarifi ver.",
        "Refused by dummy."
    )


@pytest.mark.asyncio
async def test_orchestrator_integration_passes_normally():
    mock_memory = AsyncMock(spec=RedisSessionStore)
    mock_memory.get_history.return_value = []
    mock_memory.get_metadata.return_value = {}

    mock_db = AsyncMock()
    mock_db.get_session.return_value = {"source": "USER"}
    mock_llm = AsyncMock(spec=LLMClient)
    mock_llm.model = "test-model"
    # The main ReAct loop will return final answer
    mock_llm.chat.return_value = {"content": "Final Answer: Yes, the IP is clean."}

    catalog = ToolCatalog()
    # Add a dummy tool to make sure catalog is not considered empty
    mock_tool = MagicMock()
    mock_tool.name = "dummy_tool"
    mock_tool.description = "dummy description"
    mock_tool.category = "general"
    mock_tool.to_openai_schema.return_value = {"type": "function", "function": {"name": "dummy_tool"}}
    catalog.register(mock_tool)

    orchestrator = Orchestrator(
        llm=mock_llm,
        catalog=catalog,
        memory=mock_memory,
        db_repo=mock_db,
        max_iterations=1,
        rag_enabled=False,
        guardrail_manager=GuardrailManager([DummyPassGuardrail()])
    )

    steps = []
    async for step in orchestrator.run_stream("session_123", "Can you check IP 10.10.10.10?"):
        steps.append(step)

    # Main LLM chat SHOULD be called because the guardrail passed
    mock_llm.chat.assert_called_once()
    assert len(steps) == 1
    assert steps[0].step_type == StepType.ANSWER
    assert steps[0].content == "Yes, the IP is clean."


@pytest.mark.asyncio
async def test_orchestrator_integration_siem_bypasses_guardrail():
    mock_memory = AsyncMock(spec=RedisSessionStore)
    mock_memory.get_history.return_value = []
    mock_memory.get_metadata.return_value = {}

    mock_db = AsyncMock()
    # Mock get_session to return source SIEM
    mock_db.get_session.return_value = {"source": "SIEM"}

    mock_llm = AsyncMock(spec=LLMClient)
    mock_llm.model = "test-model"
    # ReAct loop returns final answer
    mock_llm.chat.return_value = {"content": "Final Answer: Triage complete."}

    catalog = ToolCatalog()
    mock_tool = MagicMock()
    mock_tool.name = "dummy_tool"
    mock_tool.description = "dummy description"
    mock_tool.category = "general"
    mock_tool.to_openai_schema.return_value = {"type": "function", "function": {"name": "dummy_tool"}}
    catalog.register(mock_tool)

    # Instantiate orchestrator with a DummyBlockGuardrail which would normally block
    orchestrator = Orchestrator(
        llm=mock_llm,
        catalog=catalog,
        memory=mock_memory,
        db_repo=mock_db,
        max_iterations=1,
        rag_enabled=False,
        guardrail_manager=GuardrailManager([DummyBlockGuardrail()])
    )

    steps = []
    async for step in orchestrator.run_stream("session_123", "SIEM alert triggered"):
        steps.append(step)

    # 1. Main LLM chat SHOULD be called because the guardrail was bypassed for SIEM session source
    mock_llm.chat.assert_called_once()
    assert len(steps) == 1
    assert steps[0].step_type == StepType.ANSWER
    assert steps[0].content == "Triage complete."
