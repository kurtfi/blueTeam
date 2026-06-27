"""
Unit and integration tests for DAG-based attack simulation and state machine.
"""

import uuid
import pytest
from typing import Any
from unittest.mock import patch, AsyncMock, MagicMock

from attack_simulator.services.simulation import SimulationService
from attack_simulator.sender.base import AlertSender
from attack_simulator.evaluator.gateway import PlaybookRegistryGateway


class MockAlertSender(AlertSender):
    def __init__(self) -> None:
        self.sent_alerts: list[tuple[dict[str, Any], str]] = []

    async def send(self, alert_payload: dict, technique_id: str) -> str | None:
        self.sent_alerts.append((alert_payload, technique_id))
        # Return a deterministic session ID based on technique
        return f"session-{technique_id}"


class MockPlaybookGateway(PlaybookRegistryGateway):
    def find_playbooks_for_mitre(self, mitre_ids: list[str]) -> list[Any]:
        mock_pb = MagicMock()
        mock_pb.id = "PB-123"
        return [mock_pb]


@pytest.mark.asyncio
async def test_execute_dag_simulation_mitigated_path() -> None:
    """
    Verifies that a DAG scenario transitions to exit_mitigated if the defender blocks (TRUE_POSITIVE).
    """
    mock_sender = MockAlertSender()
    mock_gateway = MockPlaybookGateway()
    service = SimulationService(alert_sender=mock_sender, playbook_gateway=mock_gateway)

    run_id = str(uuid.uuid4())
    scenario_id = str(uuid.uuid4())

    dag_structure = {
        "initial_step": "step_1",
        "steps": {
            "step_1": {
                "name": "Initial Exploitation",
                "mitre_technique": "T1190",
                "wazuh_alerts": [
                    {"rule": {"id": "100001", "description": "Exploit exploit"}}
                ],
                "next": {
                    "TRUE_POSITIVE": "exit_mitigated",
                    "FALSE_POSITIVE": "step_2",
                    "NO_PLAYBOOK": "step_2",
                    "TIMEOUT": "step_2",
                }
            },
            "step_2": {
                "name": "Privilege Escalation",
                "mitre_technique": "T1003.008",
                "wazuh_alerts": [
                    {"rule": {"id": "100002", "description": "LSASS Access"}}
                ],
                "next": {
                    "TRUE_POSITIVE": "exit_mitigated",
                    "FALSE_POSITIVE": "exit_compromised",
                }
            },
            "exit_mitigated": {
                "name": "Attack Mitigated",
                "mitre_technique": "T1190",
                "wazuh_alerts": [],
                "next": None
            },
            "exit_compromised": {
                "name": "System Compromised",
                "mitre_technique": "T1003.008",
                "wazuh_alerts": [],
                "next": None
            }
        }
    }

    # Mock DB update functions, playbook check, and gateway
    with (
        patch("attack_simulator.repository.postgres.db_repo.insert_simulation_result", new_callable=AsyncMock),
        patch("attack_simulator.repository.postgres.db_repo.update_run_stats", new_callable=AsyncMock) as mock_update_stats,
        patch("attack_simulator.repository.postgres.db_repo.update_run_path", new_callable=AsyncMock) as mock_update_path,
        patch("attack_simulator.repository.postgres.db_repo.get_pool", new_callable=AsyncMock) as mock_pool,
        patch("attack_simulator.evaluator.playbook_match.get_expected_playbooks", new_callable=AsyncMock) as mock_get_expected,
        patch("attack_simulator.evaluator.playbook_match.check_actual_playbook", new_callable=AsyncMock) as mock_check,
        patch("attack_simulator.evaluator.agentix_gateway.AgentixSessionGateway.get_session_status", new_callable=AsyncMock) as mock_status,
    ):
        mock_get_expected.return_value = ["PB-123"]
        # Setup mock db pool connection for final result update
        mock_conn = AsyncMock()
        mock_acq = MagicMock()
        mock_acq.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_acq.__aexit__ = AsyncMock()
        
        mock_pool_instance = MagicMock()
        mock_pool_instance.acquire.return_value = mock_acq
        mock_pool.return_value = mock_pool_instance

        # Mock defensive agent behavior: agent runs the correct playbook "PB-123"
        mock_check.return_value = "PB-123"  # matches expected PB-123 -> TRUE_POSITIVE
        mock_status.return_value = "COMPLETED"

        # Execute DAG simulation (bypass sleep intervals inside test)
        with patch("asyncio.sleep", new_callable=AsyncMock):
            await service.execute_dag_simulation(
                run_id=run_id,
                scenario_id=scenario_id,
                dag_structure=dag_structure,
                delay_between_events=0.0,
                sender=mock_sender,
            )

        # Assert correct path traversal was recorded: step_1 -> exit_mitigated
        # It updates database for every step
        mock_update_path.assert_any_call(run_id, ["step_1"])
        mock_update_path.assert_any_call(run_id, ["step_1", "exit_mitigated"])

        # Check final updates
        mock_update_stats.assert_any_call(
            run_id=run_id,
            status="COMPLETED",
            sent_events=1,
            matched_playbooks=1,
            mismatched_playbooks=0,
            no_playbook=0,
        )


@pytest.mark.asyncio
async def test_execute_dag_simulation_compromised_path() -> None:
    """
    Verifies that a DAG scenario transitions to step_2 and then exit_compromised if defender fails (NO_PLAYBOOK).
    """
    mock_sender = MockAlertSender()
    mock_gateway = MockPlaybookGateway()
    service = SimulationService(alert_sender=mock_sender, playbook_gateway=mock_gateway)

    run_id = str(uuid.uuid4())
    scenario_id = str(uuid.uuid4())

    dag_structure = {
        "initial_step": "step_1",
        "steps": {
            "step_1": {
                "name": "Initial Exploitation",
                "mitre_technique": "T1190",
                "wazuh_alerts": [
                    {"rule": {"id": "100001", "description": "Exploit exploit"}}
                ],
                "next": {
                    "TRUE_POSITIVE": "exit_mitigated",
                    "FALSE_POSITIVE": "step_2",
                    "NO_PLAYBOOK": "step_2",
                    "TIMEOUT": "step_2",
                }
            },
            "step_2": {
                "name": "Privilege Escalation",
                "mitre_technique": "T1003.008",
                "wazuh_alerts": [
                    {"rule": {"id": "100002", "description": "LSASS Access"}}
                ],
                "next": {
                    "TRUE_POSITIVE": "exit_mitigated",
                    "FALSE_POSITIVE": "exit_compromised",
                    "NO_PLAYBOOK": "exit_compromised",
                }
            },
            "exit_mitigated": {
                "name": "Attack Mitigated",
                "mitre_technique": "T1190",
                "wazuh_alerts": [],
                "next": None
            },
            "exit_compromised": {
                "name": "System Compromised",
                "mitre_technique": "T1003.008",
                "wazuh_alerts": [],
                "next": None
            }
        }
    }

    # Mock DB functions
    with (
        patch("attack_simulator.repository.postgres.db_repo.insert_simulation_result", new_callable=AsyncMock),
        patch("attack_simulator.repository.postgres.db_repo.update_run_stats", new_callable=AsyncMock) as mock_update_stats,
        patch("attack_simulator.repository.postgres.db_repo.update_run_path", new_callable=AsyncMock) as mock_update_path,
        patch("attack_simulator.repository.postgres.db_repo.get_pool", new_callable=AsyncMock) as mock_pool,
        patch("attack_simulator.evaluator.playbook_match.get_expected_playbooks", new_callable=AsyncMock) as mock_get_expected,
        patch("attack_simulator.evaluator.playbook_match.check_actual_playbook", new_callable=AsyncMock) as mock_check,
        patch("attack_simulator.evaluator.agentix_gateway.AgentixSessionGateway.get_session_status", new_callable=AsyncMock) as mock_status,
    ):
        mock_get_expected.return_value = ["PB-123"]
        mock_conn = AsyncMock()
        mock_acq = MagicMock()
        mock_acq.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_acq.__aexit__ = AsyncMock()
        
        mock_pool_instance = MagicMock()
        mock_pool_instance.acquire.return_value = mock_acq
        mock_pool.return_value = mock_pool_instance

        # Mock defensive agent behavior: agent fails to trigger any playbook
        mock_check.return_value = None
        mock_status.return_value = "COMPLETED"

        # Execute DAG simulation (bypass sleep intervals inside test)
        with patch("asyncio.sleep", new_callable=AsyncMock):
            await service.execute_dag_simulation(
                run_id=run_id,
                scenario_id=scenario_id,
                dag_structure=dag_structure,
                delay_between_events=0.0,
                sender=mock_sender,
            )

        # Assert correct path traversal was recorded: step_1 -> step_2 -> exit_compromised
        mock_update_path.assert_any_call(run_id, ["step_1"])
        mock_update_path.assert_any_call(run_id, ["step_1", "step_2"])
        mock_update_path.assert_any_call(run_id, ["step_1", "step_2", "exit_compromised"])

        # Check final updates (two NO_PLAYBOOK failures)
        mock_update_stats.assert_any_call(
            run_id=run_id,
            status="COMPLETED",
            sent_events=2,
            matched_playbooks=0,
            mismatched_playbooks=0,
            no_playbook=2,
        )
