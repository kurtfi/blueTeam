import json
import uuid
import pytest

from agentic_common.memory import postgres_session_repo
from attack_simulator.evaluator.playbook_match import check_actual_playbook
from attack_simulator.models import db_repo


@pytest.fixture(autouse=True)
async def cleanup_db_pools():
    """Close and reset connection pools before and after each test to prevent event loop mismatch errors."""
    # Setup phase: close any pools left over from other test modules
    if postgres_session_repo._pool:
        try:
            await postgres_session_repo._pool.close()
        except Exception:
            pass
        postgres_session_repo._pool = None
        
    if db_repo._pool:
        try:
            await db_repo._pool.close()
        except Exception:
            pass
        db_repo._pool = None

    yield

    # Teardown phase: close pools after our tests to be clean
    if postgres_session_repo._pool:
        try:
            await postgres_session_repo._pool.close()
        except Exception:
            pass
        postgres_session_repo._pool = None
        
    if db_repo._pool:
        try:
            await db_repo._pool.close()
        except Exception:
            pass
        db_repo._pool = None


@pytest.mark.asyncio
async def test_check_actual_playbook_with_trigger_playbook() -> None:
    """
    Test that check_actual_playbook properly extracts playbook_id from trigger_playbook tool calls.
    """
    session_id = str(uuid.uuid4())

    # 1. Create a fake session
    await postgres_session_repo.create_session(
        session_id=session_id,
        display_name="Test Session Trigger Playbook",
        source="SIEM",
        owner_id="siem",
        agent_name="simulation_analyst",
    )

    # 2. Add events
    # Add a think event that calls trigger_playbook
    await postgres_session_repo.add_event(
        session_id=session_id,
        event_type="think",
        actor="agent",
        content="Calling tool 'trigger_playbook' with {'playbook_id': 'PB-073'}",
        metadata={"tool_name": "trigger_playbook", "tool_input": {"playbook_id": "PB-073"}},
    )

    # 3. Verify check_actual_playbook extracts PB-073
    actual = await check_actual_playbook(session_id)
    assert actual == "PB-073"


@pytest.mark.asyncio
async def test_check_actual_playbook_with_final_answer() -> None:
    """
    Test that check_actual_playbook properly extracts playbook_id from the agent's final answer using regex.
    """
    session_id = str(uuid.uuid4())

    await postgres_session_repo.create_session(
        session_id=session_id,
        display_name="Test Session Final Answer",
        source="SIEM",
        owner_id="siem",
        agent_name="simulation_analyst",
    )

    # Add an answer event mentioning the playbook
    await postgres_session_repo.add_event(
        session_id=session_id,
        event_type="answer",
        actor="agent",
        content="I have identified that the threat corresponds to PB-012 (Brute Force Playbook).",
    )

    actual = await check_actual_playbook(session_id)
    assert actual == "PB-012"


@pytest.mark.asyncio
async def test_check_actual_playbook_with_get_playbook_details() -> None:
    """
    Test that check_actual_playbook properly extracts playbook_id from get_playbook_details tool calls.
    """
    session_id = str(uuid.uuid4())

    await postgres_session_repo.create_session(
        session_id=session_id,
        display_name="Test Session Playbook Details",
        source="SIEM",
        owner_id="siem",
        agent_name="simulation_analyst",
    )

    # Add a think event that calls get_playbook_details
    await postgres_session_repo.add_event(
        session_id=session_id,
        event_type="think",
        actor="agent",
        content="Calling tool 'get_playbook_details' with {'playbook_id': 'PB-005'}",
        metadata={"tool_name": "get_playbook_details", "tool_input": {"playbook_id": "PB-005"}},
    )

    actual = await check_actual_playbook(session_id)
    assert actual == "PB-005"


@pytest.mark.asyncio
async def test_check_actual_playbook_priority() -> None:
    """
    Test that check_actual_playbook honors priority: trigger_playbook > final answer > get_playbook_details
    """
    session_id = str(uuid.uuid4())

    await postgres_session_repo.create_session(
        session_id=session_id,
        display_name="Test Session Priority",
        source="SIEM",
        owner_id="siem",
        agent_name="simulation_analyst",
    )

    # 1. Details event (PB-005)
    await postgres_session_repo.add_event(
        session_id=session_id,
        event_type="think",
        actor="agent",
        content="Calling tool 'get_playbook_details' with {'playbook_id': 'PB-005'}",
        metadata={"tool_name": "get_playbook_details", "tool_input": {"playbook_id": "PB-005"}},
    )

    # Verify details is returned when it is the only one
    assert await check_actual_playbook(session_id) == "PB-005"

    # 2. Final answer event (PB-012)
    await postgres_session_repo.add_event(
        session_id=session_id,
        event_type="answer",
        actor="agent",
        content="Final answer containing PB-012.",
    )

    # Verify final answer overrides details
    assert await check_actual_playbook(session_id) == "PB-012"

    # 3. Trigger event (PB-073)
    await postgres_session_repo.add_event(
        session_id=session_id,
        event_type="think",
        actor="agent",
        content="Calling tool 'trigger_playbook' with {'playbook_id': 'PB-073'}",
        metadata={"tool_name": "trigger_playbook", "tool_input": {"playbook_id": "PB-073"}},
    )

    # Verify trigger overrides both final answer and details
    assert await check_actual_playbook(session_id) == "PB-073"
