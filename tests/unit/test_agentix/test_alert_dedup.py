import sys
from pathlib import Path

# Add src/Agentix and src/AgenticCommon to sys.path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir))
sys.path.insert(0, str(root_dir.parent / "AgenticCommon"))

import pytest
from agentix.core.alert_dedup import AlertDeduplicator
from agentic_common.settings import settings

@pytest.mark.asyncio
async def test_alert_deduplication_flow():
    # Initialize real Redis client on test DB
    dedup = AlertDeduplicator(redis_url=settings.redis_url, window_seconds=5)
    
    # Clean up test keys first
    test_key1 = "dedup:alert:100010:10.0.0.5"
    test_key2 = "dedup:alert:100002:10.0.0.5"
    await dedup._redis.delete(test_key1, test_key2)
    
    payload_brute_force = {
        "rule": {"id": "100010"},
        "data": {"srcip": "10.0.0.5"}
    }
    
    payload_bypass = {
        "rule": {"id": "100002"},
        "data": {"srcip": "10.0.0.5"}
    }
    
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
