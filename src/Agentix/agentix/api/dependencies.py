from fastapi import Request

from agentic_common.memory.redis_preferences import RedisPreferenceStore
from agentic_common.memory.redis_store import RedisSessionStore
from agentix.registry.catalog import ToolCatalog


async def get_redis_store(request: Request) -> RedisSessionStore:
    return request.app.state.redis_store


async def get_catalog(request: Request) -> ToolCatalog:
    return request.app.state.catalog


async def get_pref_store(request: Request) -> RedisPreferenceStore:
    return request.app.state.pref_store
