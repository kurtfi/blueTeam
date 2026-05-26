import asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
import redis.asyncio as redis
from agentic_common.settings import settings

async def _test_conn(name, dsn, logic_fn):
    print(f"🔍 Testing {name}...")
    try:
        await logic_fn(dsn)
        print(f"✅ {name}: Connected successfully.")
    except Exception as e:
        print(f"❌ {name}: Failed! Error: {e}")

async def postgres_logic(dsn):
    engine = create_async_engine(dsn)
    async with engine.connect() as conn:
        await conn.execute(text("SELECT 1"))
    await engine.dispose()

async def redis_logic(dsn):
    client = redis.from_url(dsn)
    await client.ping()
    await client.aclose()

async def run():
    await _test_conn("PostgreSQL", settings.agentix_sql_databases["default"], postgres_logic)
    await _test_conn("Redis", settings.agentix_redis_databases["default"], redis_logic)

if __name__ == "__main__":
    asyncio.run(run())
