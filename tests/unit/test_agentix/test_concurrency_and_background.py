import asyncio
from unittest.mock import AsyncMock, MagicMock
import pytest
from agentic_common.memory.redis_store import RedisSessionStore
from agentix.api.server import SessionTaskManager


@pytest.mark.asyncio
async def test_redis_session_store_lock():
    # Mock redis client
    mock_redis = AsyncMock()
    # Mock set and delete
    mock_redis.set.return_value = True
    mock_redis.delete.return_value = 1

    # Create store and inject mock redis
    store = RedisSessionStore(redis_url="redis://localhost:6379/0")
    store._redis = mock_redis

    # Test acquire_lock
    success = await store.acquire_lock("session_123", expire_seconds=100)
    assert success is True
    mock_redis.set.assert_called_once_with("session:session_123:lock", "1", ex=100, nx=True)

    # Test release_lock
    await store.release_lock("session_123")
    mock_redis.delete.assert_called_once_with("session:session_123:lock")


@pytest.mark.asyncio
async def test_session_task_manager():
    manager = SessionTaskManager()

    # 1. Test queue creation
    q1 = await manager.get_or_create_queue("session_123")
    q2 = await manager.get_or_create_queue("session_123")
    assert isinstance(q1, asyncio.Queue)
    assert isinstance(q2, asyncio.Queue)
    assert len(manager.queues["session_123"]) == 2

    # 2. Test publishing steps
    step_data = {"type": "thought", "content": "Analyzing"}
    await manager.publish_step("session_123", step_data)

    item1 = await q1.get()
    item2 = await q2.get()
    assert item1 == step_data
    assert item2 == step_data

    # 3. Test queue removal
    await manager.remove_queue("session_123", q1)
    assert len(manager.queues["session_123"]) == 1

    await manager.remove_queue("session_123", q2)
    assert "session_123" not in manager.queues

    # 4. Test task registration and status check
    mock_task = MagicMock(spec=asyncio.Task)
    mock_task.done.return_value = False

    await manager.register_task("session_123", mock_task)
    assert await manager.is_running("session_123") is True

    mock_task.done.return_value = True
    assert await manager.is_running("session_123") is False

    await manager.remove_task("session_123")
    assert "session_123" not in manager.tasks


@pytest.mark.asyncio
async def test_tool_executor_fs_locks():
    from agentix.core.tool_executor import ToolExecutionEngine
    from agentic_common.base_tool import BaseTool, ToolResult

    execution_order = []

    class SlowModifyingTool(BaseTool):
        name = "write_secure_file"
        description = "Write a file safely"
        category = "system"
        parameters = {}

        async def execute(self, **kwargs):
            execution_order.append("start_modify")
            await asyncio.sleep(0.05)
            execution_order.append("end_modify")
            return ToolResult(success=True, output="File written")

    engine = ToolExecutionEngine()
    tool_map = {
        "write_secure_file": SlowModifyingTool(),
    }

    tool_calls = [
        {"id": "call_1", "function": {"name": "write_secure_file", "arguments": "{}"}},
        {"id": "call_2", "function": {"name": "write_secure_file", "arguments": "{}"}},
    ]

    results = await engine.execute_tools_parallel(
        tool_calls=tool_calls,
        tool_map=tool_map,
        session_id="session_test",
    )

    assert len(results) == 2
    assert results[0].success is True
    assert results[1].success is True

    # Since they are both file-modifying, they must be serialized:
    # First must start and end before the second starts.
    assert execution_order == ["start_modify", "end_modify", "start_modify", "end_modify"]
