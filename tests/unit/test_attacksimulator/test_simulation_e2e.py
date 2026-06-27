"""
Integration and E2E tests for AttackSimulator pipeline.
"""

import uuid
import pytest
from typing import Any
from unittest.mock import patch, AsyncMock

from attack_simulator.repository import db_repo
from attack_simulator.mcp_server import _run_simulation_task


@pytest.mark.asyncio
async def test_ingest_and_run_simulation_e2e() -> None:
    """
    Integration test: Load scenario, ingest to DB, execute mock simulation, and evaluate.
    """
    metadata: dict[str, Any] = {
        "name": "E2E Credential Dumping Test",
        "description": "LSASS memory dumping simulation",
        "mitre_ids": ["T1003.001"],
    }

    mock_alert = {
        "rule": {
            "id": "100002",
            "level": 12,
            "description": "LSASS memory dumping detected via Sysmon Process Access",
            "groups": ["sysmon", "lsass", "credential_access", "mitre_t1003"],
            "mitre": {"id": ["T1003.001"], "tactic": ["Credential Access"]},
        },
        "full_log": "Sysmon process dump test",
    }

    # 4. Ingest Scenario and Events to PostgreSQL
    scenario_id = await db_repo.create_scenario(
        name=metadata["name"] + " (Test Run)",
        description=metadata["description"],
        mitre_ids=metadata["mitre_ids"],
        source_dataset="custom",
        source_path="mock_path",
        total_events=1,
    )

    # Store scenario events
    events = [
        {
            "scenario_id": scenario_id,
            "sequence_order": 1,
            "mitre_technique": "T1003.001",
            "mitre_tactic": "Credential Access",
            "correlation_type": "direct",
            "raw_event_count": 1,
            "correlation_rule": "Test Rule",
            "wazuh_alert": mock_alert,
            "raw_log_hash": "test_hash",
        }
    ]
    await db_repo.insert_attack_events(events)

    # Verify ingestion
    db_sc = await db_repo.get_scenario_by_name(metadata["name"] + " (Test Run)")
    assert db_sc is not None
    assert db_sc["total_events"] == 1

    db_events = await db_repo.get_scenario_events(db_sc["id"])
    assert len(db_events) == 1
    assert db_events[0]["mitre_technique"] == "T1003.001"

    # 5. Execute Simulation Run in database
    run_id = await db_repo.create_run(db_sc["id"], 1, 1.0)

    # Patch HTTP sender and agent playbook checking
    dummy_session_id = str(uuid.uuid4())

    with (
        patch("attack_simulator.sender.webhook.WebhookAlertSender.send", new_callable=AsyncMock) as mock_send,
        patch("attack_simulator.evaluator.playbook_match.check_actual_playbook", new_callable=AsyncMock) as mock_check,
        patch(
            "attack_simulator.evaluator.playbook_match.get_expected_playbooks", new_callable=AsyncMock
        ) as mock_expected,
    ):
        mock_send.return_value = dummy_session_id
        mock_check.return_value = "PB-001"
        mock_expected.return_value = ["PB-001"]

        # Run background simulation task with 0 delay
        await _run_simulation_task(db_sc["id"], run_id, 0.0)

        # Check results
        run_data = await db_repo.get_run(run_id)
        assert run_data is not None
        assert run_data["status"] == "COMPLETED"
        assert run_data["matched_playbooks"] == 1

        results = await db_repo.get_run_results(run_id)
        assert len(results) == 1
        assert results[0]["match_result"] == "CORRECT"
        assert results[0]["actual_playbook"] == "PB-001"

    # 6. Cleanup test records
    await db_repo.delete_scenario(db_sc["id"])
    pool = await db_repo.get_pool()
    async with pool.acquire() as conn:
        await conn.execute("DELETE FROM simulator.simulation_runs WHERE id = $1", uuid.UUID(run_id))
