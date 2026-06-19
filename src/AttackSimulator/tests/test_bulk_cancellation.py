"""
Unit tests for Bulk Run Cancellation and Partial Completion states.
"""

import uuid
import pytest
from attack_simulator.models import db_repo
from agentic_common.memory import postgres_session_repo


@pytest.fixture(autouse=True)
async def cleanup_db_pools():
    """Close and reset connection pools before and after each test to prevent event loop mismatch errors."""
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
async def test_bulk_run_cancellation_states() -> None:
    """
    Test bulk run cancellation updates status to CANCELLED (0 sub-runs)
    and PARTIALLY_COMPLETED (some completed sub-runs).
    """
    # Create a scenario to generate runs
    scenario_id = await db_repo.create_scenario(
        name="Test Scenario for Cancellation",
        description="Cancellation testing",
        mitre_ids=["T1003.001"],
        source_dataset="custom",
        source_path="/dummy/path",
        total_events=1,
    )

    try:
        # Case A: Cancel with 0 completed sub-runs -> status should become CANCELLED
        bulk_run_id_a = await db_repo.create_bulk_run(
            name="Test Bulk Cancel A",
            llm_provider="openai",
            llm_model="gpt-4",
            strip_labels=False,
            send_rate_per_sec=1.0,
            total_scenarios=2,
        )

        bulk_a = await db_repo.get_bulk_run(bulk_run_id_a)
        assert bulk_a["status"] == "RUNNING"
        assert bulk_a["completed_at"] is None

        # Execute cancellation
        await db_repo.cancel_bulk_run(bulk_run_id_a)

        bulk_a_after = await db_repo.get_bulk_run(bulk_run_id_a)
        assert bulk_a_after["status"] == "CANCELLED"
        assert bulk_a_after["completed_scenarios"] == 0
        assert bulk_a_after["completed_at"] is not None

        # Case B: Cancel with 1 completed sub-run -> status should become PARTIALLY_COMPLETED
        bulk_run_id_b = await db_repo.create_bulk_run(
            name="Test Bulk Cancel B",
            llm_provider="openai",
            llm_model="gpt-4",
            strip_labels=False,
            send_rate_per_sec=1.0,
            total_scenarios=3,
        )

        # Create one completed run under bulk B
        run_id_1 = await db_repo.create_run(
            scenario_id=scenario_id,
            total_events=1,
            send_rate_per_sec=1.0,
            bulk_run_id=bulk_run_id_b,
        )
        # Mark the run as COMPLETED
        await db_repo.update_run_stats(
            run_id=run_id_1,
            status="COMPLETED",
            sent_events=1,
            matched_playbooks=1,
            mismatched_playbooks=0,
            no_playbook=0
        )

        # Create another run under bulk B which is still RUNNING
        run_id_2 = await db_repo.create_run(
            scenario_id=scenario_id,
            total_events=1,
            send_rate_per_sec=1.0,
            bulk_run_id=bulk_run_id_b,
        )

        # Execute cancellation
        await db_repo.cancel_bulk_run(bulk_run_id_b)

        bulk_b_after = await db_repo.get_bulk_run(bulk_run_id_b)
        assert bulk_b_after["status"] == "PARTIALLY_COMPLETED"
        assert bulk_b_after["completed_scenarios"] == 1
        assert bulk_b_after["matched_playbooks"] == 1
        assert bulk_b_after["completed_at"] is not None

    finally:
        # Clean up scenario
        await db_repo.delete_scenario(scenario_id)
