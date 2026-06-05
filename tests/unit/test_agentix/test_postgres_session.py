import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from agentic_common.memory.postgres_session import PostgresSessionRepository


def create_mock_pool(conn_mock):
    """Helper to mock asyncpg connection pool async context manager."""
    pool_mock = MagicMock()
    async_ctx = MagicMock()
    async_ctx.__aenter__ = AsyncMock(return_value=conn_mock)
    async_ctx.__aexit__ = AsyncMock(return_value=None)
    pool_mock.acquire.return_value = async_ctx
    return pool_mock


@pytest.mark.asyncio
async def test_create_session():
    conn_mock = AsyncMock()
    pool_mock = create_mock_pool(conn_mock)
    
    repo = PostgresSessionRepository(pool=pool_mock)
    
    session_id = str(uuid.uuid4())
    display_name = "Test SSH Alert"
    source = "WAZUH"
    
    res = await repo.create_session(
        session_id=session_id,
        display_name=display_name,
        source=source,
        wazuh_rule_id="100002",
        source_ip="10.10.10.99",
    )
    
    assert res == session_id
    conn_mock.execute.assert_called_once()
    args, _ = conn_mock.execute.call_args
    assert "INSERT INTO sessions" in args[0]
    assert args[1] == uuid.UUID(session_id)
    assert args[2] == display_name
    assert args[3] == source


@pytest.mark.asyncio
async def test_update_status():
    conn_mock = AsyncMock()
    pool_mock = create_mock_pool(conn_mock)
    
    repo = PostgresSessionRepository(pool=pool_mock)
    session_id = str(uuid.uuid4())
    
    await repo.update_status(session_id, "COMPLETED", "TRUE_POSITIVE")
    
    conn_mock.execute.assert_called_once()
    args, _ = conn_mock.execute.call_args
    assert "UPDATE sessions" in args[0]
    assert "completed_at" in args[0]
    assert args[1] == uuid.UUID(session_id)
    assert args[2] == "COMPLETED"
    assert args[3] == "TRUE_POSITIVE"


@pytest.mark.asyncio
async def test_increment_stats():
    conn_mock = AsyncMock()
    pool_mock = create_mock_pool(conn_mock)
    
    repo = PostgresSessionRepository(pool=pool_mock)
    session_id = str(uuid.uuid4())
    
    await repo.increment_stats(session_id, message_count=2, tool_calls=5, hitl_count=1)
    
    conn_mock.execute.assert_called_once()
    args, _ = conn_mock.execute.call_args
    assert "UPDATE sessions" in args[0]
    assert "message_count = message_count +" in args[0]
    assert args[1] == uuid.UUID(session_id)
    assert args[2] == 2
    assert args[3] == 5
    assert args[4] == 1


@pytest.mark.asyncio
async def test_get_session():
    conn_mock = AsyncMock()
    pool_mock = create_mock_pool(conn_mock)
    
    repo = PostgresSessionRepository(pool=pool_mock)
    session_id = str(uuid.uuid4())
    
    # Mock row returned by fetchrow
    mock_row = {
        "id": uuid.UUID(session_id),
        "display_name": "Test Chat",
        "source": "USER",
        "status": "ACTIVE",
        "owner_id": "user-1",
        "alert_payload": None,
    }
    conn_mock.fetchrow.return_value = mock_row
    
    res = await repo.get_session(session_id)
    
    assert res is not None
    assert res["id"] == session_id
    assert res["display_name"] == "Test Chat"
    assert res["source"] == "USER"
    conn_mock.fetchrow.assert_called_once()


@pytest.mark.asyncio
async def test_add_event():
    conn_mock = AsyncMock()
    pool_mock = create_mock_pool(conn_mock)
    
    repo = PostgresSessionRepository(pool=pool_mock)
    session_id = str(uuid.uuid4())
    
    await repo.add_event(
        session_id=session_id,
        event_type="thought",
        actor="agent",
        content="I am thinking",
        metadata={"step": 1},
    )
    
    conn_mock.execute.assert_called_once()
    args, _ = conn_mock.execute.call_args
    assert "INSERT INTO session_events" in args[0]
    assert args[1] == uuid.UUID(session_id)
    assert args[2] == "thought"
    assert args[3] == "agent"
    assert args[4] == "I am thinking"
