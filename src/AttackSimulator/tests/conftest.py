import pytest
from attack_simulator.models import db_repo


@pytest.fixture(autouse=True)
async def cleanup_db_pool():
    yield
    try:
        await db_repo.close()
    except Exception:
        pass
