from unittest.mock import AsyncMock, patch

import pytest
from agentix.api.server import app
from fastapi.testclient import TestClient

# Create FastAPI TestClient for Core API
client = TestClient(app)


@pytest.mark.asyncio
async def test_handle_siem_alert_persists():
    payload = {
        "rule": {
            "id": "100002",
            "level": 12,
            "description": "SSH Brute Force login attempt",
            "mitre": {"id": ["T1110"]},
        },
        "data": {"srcip": "192.168.1.50"},
    }

    with (
        patch(
            "agentix.api.routes.webhooks.postgres_session_repo.create_session", new_callable=AsyncMock
        ) as mock_create_session,
        patch("agentix.api.routes.webhooks.postgres_session_repo.add_event", new_callable=AsyncMock) as mock_add_event,
        patch("agentix.api.routes.webhooks.process_siem_alert") as mock_process,
        patch("agentix.api.routes.webhooks.AlertDeduplicator.check_and_register", new_callable=AsyncMock) as mock_dedup,
    ):
        mock_dedup.return_value = (False, None)
        mock_create_session.return_value = "session-uuid-123"
        app.state.deduplicator = AlertDeduplicator_mock = AsyncMock()
        AlertDeduplicator_mock.check_and_register.return_value = (False, None)

        response = client.post("/v1/webhooks/siem", json=payload)

        assert response.status_code == 200
        assert response.json()["status"] == "received"

        # Verify persistence layer was called with correct values
        mock_create_session.assert_called_once()
        kwargs = mock_create_session.call_args[1]

        assert kwargs["siem_rule_id"] == "100002"
        assert kwargs["siem_severity"] == 12
        assert kwargs["source_ip"] == "192.168.1.50"
        assert kwargs["mitre_ids"] == ["T1110"]
        assert kwargs["owner_id"] == "siem"
        assert kwargs["source"] == "SIEM"
        assert "SSH Brute Force login attempt from 192.168.1.50" in kwargs["display_name"]

        # Verify audit event and background task
        mock_add_event.assert_called_once()
        mock_process.assert_called_once()


@pytest.mark.asyncio
async def test_handle_simulation_alert_persists():
    payload = {
        "rule": {
            "id": "200001",
            "level": 8,
            "description": "Simulation login attempt",
            "mitre": {"id": ["T1078"]},
        },
        "data": {"srcip": "10.0.0.99"},
    }

    with (
        patch(
            "agentix.api.routes.webhooks.postgres_session_repo.create_session", new_callable=AsyncMock
        ) as mock_create_session,
        patch("agentix.api.routes.webhooks.postgres_session_repo.add_event", new_callable=AsyncMock) as mock_add_event,
        patch("agentix.api.routes.webhooks.process_siem_alert") as mock_process,
        patch("agentix.api.routes.webhooks.AlertDeduplicator.check_and_register", new_callable=AsyncMock) as mock_dedup,
    ):
        mock_dedup.return_value = (False, None)
        mock_create_session.return_value = "session-uuid-456"
        app.state.deduplicator = AlertDeduplicator_mock = AsyncMock()
        AlertDeduplicator_mock.check_and_register.return_value = (False, None)

        response = client.post("/v1/webhooks/simulation", json=payload)

        assert response.status_code == 200
        assert response.json()["status"] == "received"

        # Verify persistence layer was called with correct values
        mock_create_session.assert_called_once()
        kwargs = mock_create_session.call_args[1]

        assert kwargs["siem_rule_id"] == "200001"
        assert kwargs["siem_severity"] == 8
        assert kwargs["source_ip"] == "10.0.0.99"
        assert kwargs["mitre_ids"] == ["T1078"]
        assert kwargs["owner_id"] == "siem"
        assert kwargs["source"] == "SIEM"
        assert kwargs["agent_name"] == "simulation_analyst"
        assert "Simulation login attempt from 10.0.0.99" in kwargs["display_name"]

        # Verify audit event and background task with simulation_analyst parameter
        mock_add_event.assert_called_once()
        mock_process.assert_called_once()
        args, kwargs = mock_process.call_args
        assert args[2] == "simulation_analyst"
        assert args[1] == payload
