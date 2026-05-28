import pytest
import json
from unittest.mock import AsyncMock, patch, MagicMock
from agentic_common.memory.redis_store import RedisSessionStore

@pytest.fixture
def mock_redis():
    with patch("agentic_common.memory.redis_store.redis.from_url") as mock:
        client_mock = AsyncMock()
        mock.return_value = client_mock
        yield client_mock

@pytest.mark.asyncio
async def test_redis_session_store_append(mock_redis):
    store = RedisSessionStore("redis://fake")
    
    # We need a MagicMock that has async enter/exit
    pipe_mock = MagicMock()
    pipe_mock.__aenter__ = AsyncMock(return_value=pipe_mock)
    pipe_mock.__aexit__ = AsyncMock(return_value=None)
    pipe_mock.execute = AsyncMock()
    
    mock_redis.pipeline = MagicMock(return_value=pipe_mock)
    
    await store.append("sess_123", "Hello", "Hi there")
    
    # Assert rpush was called twice
    assert pipe_mock.rpush.call_count == 2
    pipe_mock.execute.assert_called_once()

@pytest.mark.asyncio
async def test_redis_session_store_get_history(mock_redis):
    store = RedisSessionStore("redis://fake")
    
    mock_redis.lrange.return_value = [
        json.dumps({"role": "user", "content": "Hello"}),
        json.dumps({"role": "assistant", "content": "Hi there"})
    ]
    
    history = await store.get_history("sess_123")
    assert len(history) == 2
    assert history[0]["role"] == "user"
    assert history[1]["role"] == "assistant"
