import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

# Add src/Agentix and src/AgenticCommon to sys.path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir))
sys.path.insert(0, str(root_dir.parent / "AgenticCommon"))

import pytest
from agentix.core.alert_dedup import AlertDeduplicator


@pytest.mark.asyncio
async def test_alert_deduplication_flow():
    # Mock redis.from_url to return a mock client
    with patch("agentix.core.alert_dedup.redis.from_url") as mock_from_url:
        mock_redis = AsyncMock()
        mock_from_url.return_value = mock_redis

        # Simulate Redis key-value store behavior using a dictionary
        store = {}

        async def mock_set(key, value, nx=False, ex=None):
            if nx and key in store:
                return None  # Redis set with nx=True returns None (or False) if key exists
            store[key] = value
            return True

        async def mock_get(key):
            return store.get(key)

        async def mock_delete(*keys):
            for k in keys:
                store.pop(k, None)
            return len(keys)

        mock_redis.set = mock_set
        mock_redis.get = mock_get
        mock_redis.delete = mock_delete
        mock_redis.aclose = AsyncMock()

        dedup = AlertDeduplicator(redis_url="redis://fake", window_seconds=5)

        # Clean up test keys first
        test_key1 = "dedup:alert:100010:10.0.0.5"
        test_key2 = "dedup:alert:100002:10.0.0.5"
        await dedup._redis.delete(test_key1, test_key2)

        payload_brute_force = {"rule": {"id": "100010"}, "data": {"srcip": "10.0.0.5"}}
        payload_bypass = {"rule": {"id": "100002"}, "data": {"srcip": "10.0.0.5"}}

        # 1. First alert should not be duplicate
        is_dup1, sid1 = await dedup.check_and_register(payload_brute_force, "session-1")
        assert not is_dup1
        assert sid1 is None

        # 2. Second alert within window should be duplicate
        is_dup2, sid2 = await dedup.check_and_register(payload_brute_force, "session-2")
        assert is_dup2
        assert sid2 == "session-1"

        # 3. Critical rules (previously bypassed, like 100002) should now be deduplicated
        is_dup3, sid3 = await dedup.check_and_register(payload_bypass, "session-3")
        assert not is_dup3
        assert sid3 is None

        is_dup4, sid4 = await dedup.check_and_register(payload_bypass, "session-4")
        assert is_dup4
        assert sid4 == "session-3"

        await dedup.aclose()
