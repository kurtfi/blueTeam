import pytest
from attack_simulator.models import db_repo
from agentic_common.memory import postgres_session_repo


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

    # Automatically execute migrations to ensure isolated 'simulator' schema exists
    try:
        await postgres_session_repo.run_migrations()
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
