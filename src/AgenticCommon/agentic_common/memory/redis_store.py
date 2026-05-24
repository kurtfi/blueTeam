"""
RedisSessionStore — Redis-backed conversation history and session metadata.
"""
from __future__ import annotations

import json
from typing import Any

import redis.asyncio as redis


class RedisSessionStore:
    """
    Redis-based async session store.
    """

    def __init__(self, redis_url: str = "redis://localhost:6379/0") -> None:
        self._redis = redis.from_url(redis_url, decode_responses=True)
        self._ttl = 86400

    async def exists(self, session_id: str) -> bool:
        history_key = f"session:{session_id}:history"
        meta_key = f"session:{session_id}:metadata"
        return await self._redis.exists(history_key, meta_key) > 0

    async def get_history(self, session_id: str) -> list[dict]:
        key = f"session:{session_id}:history"
        items = await self._redis.lrange(key, 0, -1)
        return [json.loads(item) for item in items]

    async def append(
        self,
        session_id: str,
        user_message: str,
        assistant_message: str,
    ) -> None:
        key = f"session:{session_id}:history"
        
        user_msg = json.dumps({"role": "user", "content": user_message})
        asst_msg = json.dumps({"role": "assistant", "content": assistant_message})
        
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.rpush(key, user_msg)
            pipe.rpush(key, asst_msg)
            pipe.expire(key, self._ttl)
            await pipe.execute()

    async def clear(self, session_id: str) -> None:
        history_key = f"session:{session_id}:history"
        meta_key = f"session:{session_id}:metadata"
        await self._redis.delete(history_key, meta_key)

    async def get_metadata(self, session_id: str, k: str | None = None) -> Any:
        key = f"session:{session_id}:metadata"
        if k:
            val = await self._redis.hget(key, k)
            return json.loads(val) if val else None

        data = await self._redis.hgetall(key)
        return {k: json.loads(v) for k, v in data.items()}

    async def set_metadata(self, session_id: str, k: str, value: Any) -> None:
        key = f"session:{session_id}:metadata"
        await self._redis.hset(key, k, json.dumps(value))
        await self._redis.expire(key, self._ttl)

    async def close(self) -> None:
        await self._redis.aclose()
