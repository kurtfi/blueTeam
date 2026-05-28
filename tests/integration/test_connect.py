import pytest
import asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
import redis.asyncio as redis
from agentic_common.settings import settings

@pytest.mark.asyncio
async def test_postgres_connection():
    dsn = settings.agentix_sql_databases.get("default")
    if not dsn:
        pytest.skip("PostgreSQL DSN not configured")
        
    engine = create_async_engine(dsn)
    try:
        async with engine.connect() as conn:
            result = await conn.execute(text("SELECT 1"))
            assert result.scalar() == 1
    finally:
        await engine.dispose()

@pytest.mark.asyncio
async def test_redis_connection():
    dsn = settings.agentix_redis_databases.get("default")
    if not dsn:
        pytest.skip("Redis DSN not configured")
        
    client = redis.from_url(dsn)
    try:
        ping = await client.ping()
        assert ping is True
    finally:
        await client.aclose()
