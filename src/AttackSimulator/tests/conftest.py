import pytest
from attack_simulator.models import db_repo
from agentic_common.memory import postgres_session_repo


@pytest.fixture(autouse=True)
async def cleanup_db_pool():
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
