"""
Unit tests for IngestionService and SimulationService.
"""

import uuid
import pytest
from typing import Any
from unittest.mock import patch, AsyncMock, MagicMock

from attack_simulator.exceptions import ScenarioNotFoundError, DuplicateScenarioError, SimulatorException
from attack_simulator.services.ingestion import IngestionService
from attack_simulator.services.simulation import SimulationService
from attack_simulator.sender.base import AlertSender
from attack_simulator.evaluator.gateway import PlaybookRegistryGateway


class MockAlertSender(AlertSender):
    def __init__(self) -> None:
        self.sent_alerts: list[Any] = []

    async def send(self, alert_payload: dict, technique_id: str) -> str | None:
        self.sent_alerts.append((alert_payload, technique_id))
        return "mock_session_id"


class MockPlaybookGateway(PlaybookRegistryGateway):
    def find_playbooks_for_mitre(self, mitre_ids: list[str]) -> list[Any]:
        mock_pb = MagicMock()
        mock_pb.id = "PB-MOCK"
        return [mock_pb]


@pytest.mark.asyncio
async def test_ingestion_duplicate_scenario_name() -> None:
    service = IngestionService()

    # Mock database repo returning existing scenario
    with (
        patch("attack_simulator.models.db_repo.get_scenario_by_path", new_callable=AsyncMock) as mock_get_path,
        patch("attack_simulator.models.db_repo.get_scenario_by_name", new_callable=AsyncMock) as mock_get_name,
        patch("attack_simulator.models.db_repo.get_scenario_events", new_callable=AsyncMock) as mock_get_events,
    ):
        mock_get_path.return_value = None
        mock_get_name.return_value = {"id": str(uuid.uuid4()), "name": "Existing Scenario", "total_events": 5}
        mock_get_events.return_value = [{"id": "event_id"}]

        with pytest.raises(DuplicateScenarioError):
            await service.ingest_scenario(
                path="some_path.json", source_type="custom", scenario_name="Existing Scenario"
            )


@pytest.mark.asyncio
async def test_ingestion_file_not_found() -> None:
    service = IngestionService()

    with (
        patch("attack_simulator.models.db_repo.get_scenario_by_path", new_callable=AsyncMock) as mock_get_path,
        patch("attack_simulator.models.db_repo.get_scenario_by_name", new_callable=AsyncMock) as mock_get_name,
    ):
        mock_get_path.return_value = None
        mock_get_name.return_value = None

        with pytest.raises(FileNotFoundError):
            await service.ingest_scenario(
                path="non_existing_file_xyz.json", source_type="custom", scenario_name="New Scenario"
            )


@pytest.mark.asyncio
async def test_simulation_scenario_not_found() -> None:
    service = SimulationService()

    with patch("attack_simulator.models.db_repo.get_scenario_by_name", new_callable=AsyncMock) as mock_get_name:
        mock_get_name.return_value = None

        with pytest.raises(ScenarioNotFoundError):
            await service.run_simulation(scenario_name="Non Existing Scenario")


@pytest.mark.asyncio
async def test_simulation_scenario_no_events() -> None:
    service = SimulationService()

    with (
        patch("attack_simulator.models.db_repo.get_scenario_by_name", new_callable=AsyncMock) as mock_get_name,
        patch("attack_simulator.models.db_repo.get_scenario_events", new_callable=AsyncMock) as mock_get_events,
    ):
        sc_id = str(uuid.uuid4())
        mock_get_name.return_value = {"id": sc_id, "name": "Empty Scenario"}
        mock_get_events.return_value = []

        with pytest.raises(SimulatorException):
            await service.run_simulation(scenario_name="Empty Scenario")


@pytest.mark.asyncio
async def test_simulation_execution_flow() -> None:
    mock_sender = MockAlertSender()
    mock_gateway = MockPlaybookGateway()
    service = SimulationService(alert_sender=mock_sender, playbook_gateway=mock_gateway)

    run_id = str(uuid.uuid4())
    scenario_id = str(uuid.uuid4())
    events = [
        {
            "id": str(uuid.uuid4()),
            "mitre_technique": "T1003.001",
            "wazuh_alert": {
                "rule": {
                    "id": "100002",
                    "description": "Suspicious LSASS memory access",
                    "groups": ["sysmon", "windows"],
                    "mitre": {"id": ["T1003.001"], "tactic": ["Credential Access"]},
                }
            },
        }
    ]

    with (
        patch("attack_simulator.models.db_repo.insert_simulation_result", new_callable=AsyncMock) as mock_insert,
        patch("attack_simulator.models.db_repo.update_run_stats", new_callable=AsyncMock) as mock_update,
        patch("attack_simulator.services.simulation.evaluate_run", new_callable=AsyncMock) as mock_eval,
    ):
        # Execute simulation synchronously for the test
        await service.execute_simulation(
            run_id=run_id, scenario_id=scenario_id, events=events, delay_between_events=0.0, strip_labels=True
        )

        # Verify alert was sent and label-stripped
        assert len(mock_sender.sent_alerts) == 1
        sent_alert, tech_id = mock_sender.sent_alerts[0]
        assert tech_id == "T1003.001"
        assert sent_alert["simulation_run_id"] == run_id

        # Verify mitre block and rule ID were stripped on-the-fly
        assert "mitre" not in sent_alert["rule"]
        assert sent_alert["rule"]["id"] == "999999"

        # Verify DB insertions and updates were called
        mock_insert.assert_called_once()
        assert mock_update.call_count == 1  # only RUNNING since evaluate_run is mocked
        mock_eval.assert_called_once_with(run_id)
