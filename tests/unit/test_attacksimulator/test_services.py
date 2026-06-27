"""
Unit tests for IngestionService and SimulationService using Dependency Injection.
"""

import uuid
import pytest
from typing import Any
from unittest.mock import patch, AsyncMock, MagicMock

from attack_simulator.exceptions import ScenarioNotFoundError, SimulatorException
from attack_simulator.services.simulation import SimulationService
from attack_simulator.sender.base import AlertSender
from attack_simulator.evaluator.gateway import PlaybookRegistryGateway
from attack_simulator.repository.base import SimulationRepository


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


class FakeSimulationRepository(SimulationRepository):
    def __init__(self) -> None:
        self.get_scenario_by_name = AsyncMock()
        self.get_scenario_events = AsyncMock()
        self.create_run = AsyncMock()
        self.insert_simulation_result = AsyncMock()
        self.update_run_stats = AsyncMock()
        self.update_run_path = AsyncMock()
        self.get_run = AsyncMock()
        self.get_scenario_by_id = AsyncMock()
        self.create_bulk_run = AsyncMock()
        self.get_bulk_run_status = AsyncMock()
        self.get_scenario_total_events = AsyncMock()
        self.get_active_bulk_runs = AsyncMock()
        self.get_runs_for_bulk = AsyncMock()
        self.update_bulk_run_stats = AsyncMock()
        self.cancel_bulk_run = AsyncMock()
        self.update_simulation_result_actual = AsyncMock()


@pytest.mark.asyncio
async def test_simulation_scenario_not_found() -> None:
    mock_db = FakeSimulationRepository()
    mock_db.get_scenario_by_name.return_value = None
    service = SimulationService(db_repository=mock_db)

    with pytest.raises(ScenarioNotFoundError):
        await service.run_simulation(scenario_name="Non Existing Scenario")


@pytest.mark.asyncio
async def test_simulation_scenario_no_events() -> None:
    mock_db = FakeSimulationRepository()
    sc_id = str(uuid.uuid4())
    mock_db.get_scenario_by_name.return_value = {"id": sc_id, "name": "Empty Scenario"}
    mock_db.get_scenario_events.return_value = []
    service = SimulationService(db_repository=mock_db)

    with pytest.raises(SimulatorException):
        await service.run_simulation(scenario_name="Empty Scenario")


@pytest.mark.asyncio
async def test_simulation_execution_flow() -> None:
    mock_sender = MockAlertSender()
    mock_gateway = MockPlaybookGateway()
    mock_db = FakeSimulationRepository()
    service = SimulationService(
        alert_sender=mock_sender,
        playbook_gateway=mock_gateway,
        db_repository=mock_db,
    )

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

    with patch("attack_simulator.services.simulation.evaluate_run", new_callable=AsyncMock) as mock_eval:
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
        mock_db.insert_simulation_result.assert_called_once()
        assert mock_db.update_run_stats.call_count == 1  # only RUNNING since evaluate_run is mocked
        mock_eval.assert_called_once_with(run_id)
