import sys
from pathlib import Path

# Add src/Agentix and src/AgenticCommon to sys.path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir))
sys.path.insert(0, str(root_dir.parent / "AgenticCommon"))

import pytest
from unittest.mock import AsyncMock, MagicMock, patch, ANY
from agentix.core.orchestrator import Orchestrator
from agentix.core.react import StepType, ReActStep
from agentix.registry.catalog import ToolCatalog
from agentic_common.memory.redis_store import RedisSessionStore
from agentic_common.base_tool import ToolResult

@pytest.mark.asyncio
async def test_orchestrator_saves_draft_history_on_confirm():
    # Setup mocks
    mock_memory = AsyncMock(spec=RedisSessionStore)
    mock_memory.get_history.return_value = []
    mock_memory.get_metadata.return_value = {}
    
    mock_tool = MagicMock()
    mock_tool.name = "isolate_endpoint"
    mock_tool.description = "isolate endpoint from network"
    mock_tool.category = "action"
    mock_tool.requires_confirmation.return_value = True
    mock_tool.to_openai_schema.return_value = {
        "type": "function",
        "function": {"name": "isolate_endpoint", "description": "isolate endpoint from network"}
    }
    
    catalog = ToolCatalog()
    catalog.register(mock_tool)
    
    orchestrator = Orchestrator(catalog=catalog, memory=mock_memory, max_iterations=1, rag_enabled=False)
    
    # Mock LLM returning a tool call requiring confirmation
    orchestrator._llm = AsyncMock()
    orchestrator._llm.model = "test-model"
    orchestrator._llm.chat.return_value = {
        "role": "assistant",
        "content": "Need to isolate endpoint",
        "tool_calls": [{
            "id": "call_123",
            "type": "function",
            "function": {
                "name": "isolate_endpoint",
                "arguments": '{"agent_id": "007"}'
            }
        }]
    }
    
    steps = []
    async for step in orchestrator.run_stream("session_123", "Run isolation"):
        steps.append(step)
        
    # Verify that StepType.CONFIRM was yielded
    confirm_steps = [s for s in steps if s.step_type == StepType.CONFIRM]
    assert len(confirm_steps) == 1
    assert confirm_steps[0].tool_name == "isolate_endpoint"
    
    # Verify that messages list was saved as draft_history in metadata
    mock_memory.set_metadata.assert_called_with(
        "session_123",
        "draft_history",
        ANY
    )

@pytest.mark.asyncio
async def test_orchestrator_resumes_from_draft_history():
    # Setup mock memory with draft_history metadata
    mock_memory = AsyncMock(spec=RedisSessionStore)
    mock_memory.get_history.return_value = []
    
    draft_history = [
        {"role": "system", "content": "System prompt"},
        {"role": "user", "content": "Run isolation"},
        {
            "role": "assistant",
            "content": "Need to isolate endpoint",
            "tool_calls": [{
                "id": "call_123",
                "type": "function",
                "function": {
                    "name": "isolate_endpoint",
                    "arguments": '{"agent_id": "007"}'
                }
            }]
        }
    ]
    mock_memory.get_metadata.return_value = {
        "draft_history": draft_history
    }
    
    mock_tool = MagicMock()
    mock_tool.name = "isolate_endpoint"
    mock_tool.description = "isolate endpoint from network"
    mock_tool.category = "action"
    mock_tool.requires_confirmation = MagicMock(return_value=True)
    # The tool should succeed when actually run
    mock_tool.execute = AsyncMock(return_value=ToolResult(success=True, output="Endpoint isolated successfully."))
    mock_tool.to_openai_schema = MagicMock(return_value={
        "type": "function",
        "function": {"name": "isolate_endpoint", "description": "isolate endpoint from network"}
    })
    
    catalog = ToolCatalog()
    catalog.register(mock_tool)
    
    orchestrator = Orchestrator(catalog=catalog, memory=mock_memory, max_iterations=2, rag_enabled=False)
    orchestrator._llm = AsyncMock()
    orchestrator._llm.model = "test-model"
    # Second turn should output final answer
    orchestrator._llm.chat.return_value = {
        "role": "assistant",
        "content": "Final Answer: Isolation is complete."
    }
    
    steps = []
    # User message "yes" approves the action
    async for step in orchestrator.run_stream("session_123", "yes"):
        steps.append(step)
        
    # Check that draft_history was deleted from metadata
    mock_memory.set_metadata.assert_any_call("session_123", "draft_history", None)
    
    # Check that the tool was executed
    mock_tool.execute.assert_called_once()
    
    # Check intermediate steps
    observe_steps = [s for s in steps if s.step_type == StepType.OBSERVE]
    assert len(observe_steps) == 1
    assert "Endpoint isolated successfully." in observe_steps[0].content
    
    # Check final answer
    answer_steps = [s for s in steps if s.step_type == StepType.ANSWER]
    assert len(answer_steps) == 1
    assert "Isolation is complete." in answer_steps[0].content
