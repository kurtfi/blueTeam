import asyncio
import json
import uuid
from agentic_common.settings import settings
from agentic_common.memory.redis_store import RedisSessionStore
from agentic_common.memory.redis_preferences import RedisPreferenceStore
from general_mcp.tools.ux.session_tracker import manage_session_metadata
from general_mcp.tools.ux.preference_manager import manage_preferences

async def test_ux_tools():
    session_id = f"test-session-{uuid.uuid4()}"
    user_id = "test-user-123"
    
    # 1. Initialize Stores
    session_store = RedisSessionStore(redis_url=settings.redis_url)
    pref_store = RedisPreferenceStore(redis_url=settings.redis_url)
    
    # Override global stores in modules
    import general_mcp.tools.ux.session_tracker as st_module
    import general_mcp.tools.ux.preference_manager as pm_module
    st_module._store = session_store
    pm_module._store = pref_store
    
    try:
        # --- SESSION TRACKER TEST ---
        print(f"Testing SessionTracker with session {session_id}...")
        
        # Pre-set some metadata in the "real" store
        await session_store.set_metadata(session_id, "current_step", "verification")
        
        # Test Get
        res_get = await manage_session_metadata(operation="get", session_id=session_id, key="current_step")
        print(f"GET result: {res_get}")
        assert res_get == "verification"
        
        # Test Set
        res_set = await manage_session_metadata(operation="set", session_id=session_id, key="new_key", value="new_value")
        print(f"SET result: {res_set}")
        
        # Verify in store
        meta = await session_store.get_metadata(session_id)
        print(f"Metadata in store: {meta}")
        assert meta.get("new_key") == "new_value"
        
        # --- PREFERENCE MANAGER TEST ---
        print(f"\nTesting PreferenceManager with user {user_id}...")
        
        # Test Set
        res_pref_set = await manage_preferences(
            operation="set", user_id=user_id, key="theme", value="dark"
        )
        print(f"PREF SET result: {res_pref_set}")
        assert res_pref_set == "OK"
        
        # Verify in Redis directly via store
        val = await pref_store.get(user_id, "theme")
        print(f"Preference in store: {val}")
        assert val == "dark"
        
        # Test Get
        res_pref_get = await manage_preferences(
            operation="get", user_id=user_id, key="theme"
        )
        print(f"PREF GET result: {res_pref_get}")
        assert res_pref_get == "dark"

        print("\nAll tests passed successfully!")
        
    finally:
        await session_store.clear(session_id)
        await pref_store.clear_user(user_id)
        await session_store.close()
        await pref_store.close()

if __name__ == "__main__":
    async def run():
        try:
            await test_ux_tools()
        except Exception as e:
            print(f"Test failed: {e}")
            import traceback
            traceback.print_exc()

    asyncio.run(run())
