import pytest
from agentic_common.memory.preferences import PreferenceStore


@pytest.mark.asyncio
async def test_preference_store():
    store = PreferenceStore()
    
    await store.set("user_1", "theme", "dark")
    val = await store.get("user_1", "theme")
    assert val == "dark"
    
    val_default = await store.get("user_1", "lang", "en")
    assert val_default == "en"
    
    all_prefs = await store.get_all("user_1")
    assert all_prefs == {"theme": "dark"}
    
    await store.delete("user_1", "theme")
    assert await store.get("user_1", "theme") is None
    
    await store.set("user_1", "color", "blue")
    await store.clear_user("user_1")
    assert await store.get_all("user_1") == {}
