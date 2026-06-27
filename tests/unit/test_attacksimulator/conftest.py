import pytest
from attack_simulator.repository import db_repo
from agentic_common.memory import postgres_session_repo


@pytest.fixture(scope="session", autouse=True)
def run_migrations_once():
    import asyncio
    from agentic_common.memory import postgres_session_repo

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(postgres_session_repo.run_migrations())
    except Exception as e:
        print(f"\n[Warning] Migration run failed: {e}\n")
    finally:
        if postgres_session_repo._pool:
            try:
                loop.run_until_complete(postgres_session_repo._pool.close())
            except Exception:
                pass
            postgres_session_repo._pool = None
        loop.close()


@pytest.fixture(autouse=True)
async def cleanup_db_pool():
    # Close any existing pools left over from other loops before setup
    try:
        await db_repo.close()
    except Exception:
        pass
    try:
        if postgres_session_repo._pool:
            await postgres_session_repo._pool.close()
            postgres_session_repo._pool = None
    except Exception:
        pass

    yield

    try:
        await db_repo.close()
    except Exception:
        pass
    try:
        if postgres_session_repo._pool:
            await postgres_session_repo._pool.close()
            postgres_session_repo._pool = None
    except Exception:
        pass
