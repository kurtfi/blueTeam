from unittest.mock import AsyncMock, MagicMock

import pytest
from agentix.tools.mcp_adapter import MCPToolAdapter


@pytest.fixture
def base_adapter():
    client_mock = AsyncMock()
    return MCPToolAdapter(
        name="test_tool",
        description="A test tool",
        parameters={"properties": {}},
        client=client_mock,
        max_retries=1,
        retry_delay=0.01,  # fast retries for tests
    )


def test_mcp_adapter_properties(base_adapter):
    assert base_adapter.name == "test_tool"
    assert base_adapter.description == "A test tool"
    assert base_adapter.parameters == {"properties": {}}
    assert base_adapter.requires_sandbox is True


def test_requires_confirmation(base_adapter):
    assert base_adapter.requires_confirmation() is False

    adapter2 = MCPToolAdapter(name="delete_file", description="del", parameters={}, client=AsyncMock())
    assert adapter2.requires_confirmation() is True


@pytest.mark.asyncio
async def test_execute_success(base_adapter):
    # Mock the client
    call_result_mock = MagicMock()
    call_result_mock.content = [MagicMock(text="success_output")]
    base_adapter._client.call_tool.return_value = call_result_mock

    res = await base_adapter.execute(context={}, arg1="val1")

    assert res.success is True
    assert res.output == "success_output"
    base_adapter._client.call_tool.assert_called_once_with("test_tool", arguments={"arg1": "val1"})


@pytest.mark.asyncio
async def test_execute_with_context_injection():
    client_mock = AsyncMock()
    adapter = MCPToolAdapter(
        name="test_tool",
        description="test",
        parameters={"properties": {"workspace_path": {"type": "string"}, "session_id": {"type": "string"}}},
        client=client_mock,
    )

    call_result_mock = MagicMock()
    call_result_mock.content = [MagicMock(text="ok")]
    client_mock.call_tool.return_value = call_result_mock

    context = {"workspace_path": "/tmp/ws", "session_id": "123", "user_id": "u1"}

    await adapter.execute(context=context, other_arg="abc")

    # Should inject workspace_path and session_id since they are in properties,
    # but not user_id since it's missing from properties.
    client_mock.call_tool.assert_called_once_with(
        "test_tool", arguments={"other_arg": "abc", "workspace_path": "/tmp/ws", "session_id": "123"}
    )


@pytest.mark.asyncio
async def test_execute_permanent_error(base_adapter):
    base_adapter._client.call_tool.side_effect = PermissionError("Access denied")

    res = await base_adapter.execute()

    assert res.success is False
    assert "Access denied" in res.error
    # Should not retry
    assert base_adapter._client.call_tool.call_count == 1


@pytest.mark.asyncio
async def test_execute_transient_error_retry(base_adapter):
    call_result_mock = MagicMock()
    call_result_mock.content = [MagicMock(text="ok_after_retry")]

    # Fail first time, succeed second time
    base_adapter._client.call_tool.side_effect = [ConnectionError("timeout"), call_result_mock]

    res = await base_adapter.execute()

    assert res.success is True
    assert res.output == "ok_after_retry"
    assert base_adapter._client.call_tool.call_count == 2


@pytest.mark.asyncio
async def test_execute_transient_error_max_retries(base_adapter):
    base_adapter._client.call_tool.side_effect = ConnectionError("timeout")

    res = await base_adapter.execute()

    assert res.success is False
    assert "timeout" in res.error
    # 1 initial + 1 retry = 2 calls
    assert base_adapter._client.call_tool.call_count == 2


def test_parse_result():
    # Test JSON string parsing
    mock1 = MagicMock()
    mock1.text = '{"key": "value"}'

    mock_result = MagicMock()
    mock_result.content = [mock1]

    parsed = MCPToolAdapter._parse_result(mock_result)
    assert parsed == {"key": "value"}

    # Test list format
    mock2 = MagicMock()
    mock2.text = "plain text"
    parsed_list = MCPToolAdapter._parse_result([mock2])
    assert parsed_list == "plain text"

    # Test plain text list dict
    parsed_dict = MCPToolAdapter._parse_result([{"text": "hello"}])
    assert parsed_dict == "hello"


@pytest.mark.asyncio
async def test_interrupt_hooks(base_adapter):
    before_hook = AsyncMock()
    after_hook = AsyncMock()

    base_adapter._interrupt_before = before_hook
    base_adapter._interrupt_after = after_hook

    call_result_mock = MagicMock()
    call_result_mock.content = [MagicMock(text="ok")]
    base_adapter._client.call_tool.return_value = call_result_mock

    context = {"k": "v"}
    await base_adapter.execute(context=context, arg1="test")

    before_hook.assert_called_once_with(tool_name="test_tool", args={"arg1": "test"}, context=context)
    after_hook.assert_called_once_with(tool_name="test_tool", args={"arg1": "test"}, result="ok", context=context)
