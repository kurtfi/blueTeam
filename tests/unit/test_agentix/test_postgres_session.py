import uuid
from unittest.mock import AsyncMock, MagicMock, patch

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
    source = "SIEM"

    res = await repo.create_session(
        session_id=session_id,
        display_name=display_name,
        source=source,
        siem_rule_id="100002",
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


@pytest.mark.asyncio
@patch("asyncpg.create_pool")
@patch("agentic_common.memory.postgres_session.logger")
async def test_get_pool_retry_behavior(mock_logger, mock_create_pool):
    repo = PostgresSessionRepository()
    mock_create_pool.side_effect = Exception("DB Connection Refused")

    with patch("asyncio.sleep", AsyncMock()) as mock_sleep:
        with pytest.raises(Exception, match="DB Connection Refused"):
            await repo.get_pool()

        assert mock_create_pool.call_count == 3
        assert mock_sleep.call_count == 2
        mock_logger.critical.assert_called_once_with(
            "postgres_session.connection_failed_final",
            error="DB Connection Refused",
            alert=True,
            db_failure=True,
        )


@pytest.mark.asyncio
async def test_register_agent_in_db():
    conn_mock = AsyncMock()
    pool_mock = create_mock_pool(conn_mock)
    repo = PostgresSessionRepository(pool=pool_mock)

    await repo.register_agent_in_db("test_agent", "configs/test_agent.yaml")

    conn_mock.execute.assert_called_once()
    args, _ = conn_mock.execute.call_args
    assert "INSERT INTO agents" in args[0]
    assert args[1] == "test_agent"
    assert args[2] == "configs/test_agent.yaml"


@pytest.mark.asyncio
async def test_register_playbook_in_db():
    conn_mock = AsyncMock()
    pool_mock = create_mock_pool(conn_mock)
    repo = PostgresSessionRepository(pool=pool_mock)

    await repo.register_playbook_in_db("PB-999", "definitions/pb_999.yaml")

    conn_mock.execute.assert_called_once()
    args, _ = conn_mock.execute.call_args
    assert "INSERT INTO playbooks" in args[0]
    assert args[1] == "PB-999"
    assert args[2] == "definitions/pb_999.yaml"


@pytest.mark.asyncio
async def test_map_agent_to_playbook():
    conn_mock = AsyncMock()
    pool_mock = create_mock_pool(conn_mock)
    repo = PostgresSessionRepository(pool=pool_mock)

    await repo.map_agent_to_playbook("test_agent", "PB-999")

    conn_mock.execute.assert_called_once()
    args, _ = conn_mock.execute.call_args
    assert "INSERT INTO agent_playbooks" in args[0]
    assert args[1] == "test_agent"
    assert args[2] == "PB-999"


@pytest.mark.asyncio
async def test_get_allowed_playbooks_for_agent():
    conn_mock = AsyncMock()
    pool_mock = create_mock_pool(conn_mock)
    repo = PostgresSessionRepository(pool=pool_mock)

    mock_rows = [
        {"playbook_id": "PB-001"},
        {"playbook_id": "PB-003"},
    ]
    conn_mock.fetch.return_value = mock_rows

    res = await repo.get_allowed_playbooks_for_agent("test_agent")

    assert res == ["PB-001", "PB-003"]
    conn_mock.fetch.assert_called_once_with(
        "SELECT playbook_id FROM agent_playbooks WHERE agent_id = $1",
        "test_agent",
    )


@pytest.mark.asyncio
async def test_count_sessions_filter_agent():
    conn_mock = AsyncMock()
    pool_mock = create_mock_pool(conn_mock)
    repo = PostgresSessionRepository(pool=pool_mock)

    conn_mock.fetchval.return_value = 5

    res = await repo.count_sessions(agent_name="soc_analyst")

    assert res == 5
    conn_mock.fetchval.assert_called_once()
    args, _ = conn_mock.fetchval.call_args
    assert "agent_name = $1" in args[0]
    assert args[1] == "soc_analyst"


@pytest.mark.asyncio
async def test_list_sessions_filter_agent():
    conn_mock = AsyncMock()
    pool_mock = create_mock_pool(conn_mock)
    repo = PostgresSessionRepository(pool=pool_mock)

    mock_id = uuid.uuid4()
    mock_rows = [
        {
            "id": mock_id,
            "display_name": "Test Session",
            "source": "SIEM",
            "status": "ACTIVE",
            "owner_id": "admin",
            "agent_name": "simulation_analyst",
            "alert_payload": None,
        }
    ]
    conn_mock.fetch.return_value = mock_rows

    res = await repo.list_sessions(agent_name="simulation_analyst")

    assert len(res) == 1
    assert res[0]["id"] == str(mock_id)
    assert res[0]["agent_name"] == "simulation_analyst"
    conn_mock.fetch.assert_called_once()
    args, _ = conn_mock.fetch.call_args
    assert "agent_name = $1" in args[0]
    assert args[1] == "simulation_analyst"
