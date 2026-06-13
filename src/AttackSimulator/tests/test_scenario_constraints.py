"""
Tests for character length validations, scenario activation constraints, and duplication checks.
"""

import os
import uuid
import pytest
from unittest.mock import patch, MagicMock, AsyncMock

from attack_simulator.models import db_repo
from attack_simulator import mcp_server


@pytest.mark.asyncio
async def test_single_active_scenario_constraint() -> None:
    """
    Verifies that activating a scenario deactivates all other scenarios and their events.
    """
    # 1. Create two scenarios
    scenario_a_id = await db_repo.create_scenario(
        name="Scenario A Test",
        description="First test scenario",
        mitre_ids=["T1003"],
        source_dataset="mordor",
        source_path="/path/to/a",
        status="passive"
    )
    scenario_b_id = await db_repo.create_scenario(
        name="Scenario B Test",
        description="Second test scenario",
        mitre_ids=["T1027"],
        source_dataset="mordor",
        source_path="/path/to/b",
        status="passive"
    )

    try:
        # Create events for both scenarios
        events_a = [{
            "scenario_id": scenario_a_id,
            "sequence_order": 1,
            "mitre_technique": "T1003",
            "mitre_tactic": "Credential Access",
            "correlation_type": "direct",
            "raw_event_count": 1,
            "correlation_rule": "Rule A",
            "wazuh_alert": {},
            "raw_log_hash": "hash_a"
        }]
        events_b = [{
            "scenario_id": scenario_b_id,
            "sequence_order": 1,
            "mitre_technique": "T1027",
            "mitre_tactic": "Defense Evasion",
            "correlation_type": "direct",
            "raw_event_count": 1,
            "correlation_rule": "Rule B",
            "wazuh_alert": {},
            "raw_log_hash": "hash_b"
        }]
        await db_repo.insert_attack_events(events_a, status="passive")
        await db_repo.insert_attack_events(events_b, status="passive")

        # 2. Activate scenario A
        await db_repo.activate_scenario(scenario_a_id)

        # Retrieve scenarios
        scenarios = await db_repo.list_scenarios()
        sc_a = next(s for s in scenarios if s["id"] == scenario_a_id)
        sc_b = next(s for s in scenarios if s["id"] == scenario_b_id)

        assert sc_a["status"] == "active"
        assert sc_b["status"] == "passive"

        events_a_db = await db_repo.get_scenario_events(scenario_a_id)
        events_b_db = await db_repo.get_scenario_events(scenario_b_id)
        assert events_a_db[0]["status"] == "active"
        assert events_b_db[0]["status"] == "passive"

        # 3. Activate scenario B
        await db_repo.activate_scenario(scenario_b_id)

        scenarios = await db_repo.list_scenarios()
        sc_a = next(s for s in scenarios if s["id"] == scenario_a_id)
        sc_b = next(s for s in scenarios if s["id"] == scenario_b_id)

        assert sc_a["status"] == "passive"
        assert sc_b["status"] == "active"

        events_a_db = await db_repo.get_scenario_events(scenario_a_id)
        events_b_db = await db_repo.get_scenario_events(scenario_b_id)
        assert events_a_db[0]["status"] == "passive"
        assert events_b_db[0]["status"] == "active"

    finally:
        # Cleanup
        await db_repo.delete_scenario(scenario_a_id)
        await db_repo.delete_scenario(scenario_b_id)


@pytest.mark.asyncio
async def test_mcp_character_length_validations() -> None:
    """
    Verifies that mcp_server tools reject input arguments exceeding character limits.
    """
    # 1. trigger_attack_simulation scenario_name limit 255
    res1 = await mcp_server.trigger_attack_simulation("A" * 256)
    assert "exceeds 255 characters" in res1

    # 2. get_simulation_run_status run_id limit 100
    res2 = await mcp_server.get_simulation_run_status("B" * 101)
    assert "exceeds 100 characters" in res2

    # 3. activate_scenario scenario_name limit 255
    res3 = await mcp_server.activate_scenario("C" * 256)
    assert "exceeds 255 characters" in res3

    # 4. download_mordor_scenario url limit 1000
    res4 = await mcp_server.download_mordor_scenario("http://" + "D" * 1000)
    assert "exceeds 1000 characters" in res4


@pytest.mark.asyncio
async def test_download_mordor_scenario_duplicate_checks() -> None:
    """
    Verifies that download_mordor_scenario blocks downloads if the file or scenario already exists.
    """
    url = "https://example.com/test_duplicate_scenario.zip"
    dest_path = os.path.abspath(os.path.join("data", "test_duplicate_scenario.zip"))

    # Test Case 1: Local file already exists (size > 100)
    with patch("os.path.exists", return_value=True), \
         patch("os.path.getsize", return_value=150):
        res = await mcp_server.download_mordor_scenario(url)
        assert "already downloaded" in res

    # Test Case 2: Scenario and events already exist in DB
    scenario_id = str(uuid.uuid4())
    with patch("os.path.exists", return_value=False), \
         patch.object(db_repo, "get_scenario_by_path", return_value={"id": scenario_id, "name": "Test"}), \
         patch.object(db_repo, "get_scenario_events", return_value=[{"id": "event_id"}]):
        res = await mcp_server.download_mordor_scenario(url)
        assert "already ingested and has events" in res
