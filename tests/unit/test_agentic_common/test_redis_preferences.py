import json
from unittest.mock import AsyncMock, patch

import pytest
from agentic_common.memory.redis_preferences import RedisPreferenceStore


@pytest.fixture
def mock_redis():
    with patch("agentic_common.memory.redis_preferences.redis.from_url") as mock:
        client_mock = AsyncMock()
        mock.return_value = client_mock
        yield client_mock

@pytest.mark.asyncio
async def test_redis_preference_store(mock_redis):
    store = RedisPreferenceStore("redis://fake")
    
    # Test set
    await store.set("user_1", "theme", "dark")
    mock_redis.hset.assert_called_once_with("user:user_1:preferences", "theme", json.dumps("dark"))
    
    # Test get
    mock_redis.hget.return_value = json.dumps("dark")
    val = await store.get("user_1", "theme")
    assert val == "dark"
    
    # Test get missing with default
    mock_redis.hget.return_value = None
    val_def = await store.get("user_1", "lang", "tr")
    assert val_def == "tr"
    
    # Test get_all
    mock_redis.hgetall.return_value = {"theme": json.dumps("dark"), "lang": json.dumps("en")}
    all_prefs = await store.get_all("user_1")
    assert all_prefs == {"theme": "dark", "lang": "en"}
    
    # Test delete
    await store.delete("user_1", "theme")
    mock_redis.hdel.assert_called_once_with("user:user_1:preferences", "theme")
    
    # Test clear_user
    await store.clear_user("user_1")
    mock_redis.delete.assert_called_once_with("user:user_1:preferences")
    
    # Test close
    await store.close()
    mock_redis.aclose.assert_called_once()
