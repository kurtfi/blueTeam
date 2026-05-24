"""
RedisPreferenceStore — persistent user preference management via Redis.
"""
from __future__ import annotations

import json
from typing import Any

import redis.asyncio as redis


class RedisPreferenceStore:
    """
    Redis-based async preference store.
    """

    def __init__(self, redis_url: str = "redis://localhost:6379/0") -> None:
        self._redis = redis.from_url(redis_url, decode_responses=True)

    async def get(self, user_id: str, key: str, default: Any = None) -> Any:
        redis_key = f"user:{user_id}:preferences"
        val = await self._redis.hget(redis_key, key)
        return json.loads(val) if val is not None else default

    async def get_all(self, user_id: str) -> dict[str, Any]:
        redis_key = f"user:{user_id}:preferences"
        data = await self._redis.hgetall(redis_key)
        return {k: json.loads(v) for k, v in data.items()}

    async def set(self, user_id: str, key: str, value: Any) -> None:
        redis_key = f"user:{user_id}:preferences"
        await self._redis.hset(redis_key, key, json.dumps(value))

    async def delete(self, user_id: str, key: str) -> None:
        redis_key = f"user:{user_id}:preferences"
        await self._redis.hdel(redis_key, key)

    async def clear_user(self, user_id: str) -> None:
        redis_key = f"user:{user_id}:preferences"
        await self._redis.delete(redis_key)

    async def close(self) -> None:
        await self._redis.aclose()
