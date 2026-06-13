import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

# Add src/Agentix and src/AgenticCommon to sys.path
root_dir = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(root_dir / "src" / "Agentix"))
sys.path.insert(0, str(root_dir / "src" / "AgenticCommon"))

with patch("gateway.security.auth.auth_store.setup_db", new_callable=AsyncMock):
    from gateway.main import app
    from gateway.security.auth import create_access_token


@pytest.fixture
def client():
    c = TestClient(app)
    c.cookies.clear()
    return c


@pytest.mark.asyncio
async def test_list_scenarios_gateway_success(client):
    token = create_access_token(
        data={"uid": "test-user-123", "email": "test-user@agentix.ai", "role": "admin", "permissions": ["read"]}
    )

    with patch("gateway.services.agentix_client.list_sim_scenarios", new_callable=AsyncMock) as mock_list:
        mock_list.return_value = [
            {"id": "sc-1", "name": "Scenario 1", "status": "active", "total_events": 5}
        ]

        response = client.get("/web/simulations/scenarios", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["name"] == "Scenario 1"
        mock_list.assert_called_once()


@pytest.mark.asyncio
async def test_activate_scenario_gateway_success(client):
    token = create_access_token(
        data={"uid": "test-user-123", "email": "test-user@agentix.ai", "role": "admin", "permissions": ["read"]}
    )

    with patch("gateway.services.agentix_client.activate_sim_scenario", new_callable=AsyncMock) as mock_activate:
        mock_activate.return_value = {"status": "success", "message": "Scenario activated"}

        response = client.post("/web/simulations/scenarios/sc-1/activate", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        mock_activate.assert_called_once_with("sc-1")


@pytest.mark.asyncio
async def test_run_scenario_gateway_success(client):
    token = create_access_token(
        data={"uid": "test-user-123", "email": "test-user@agentix.ai", "role": "admin", "permissions": ["read"]}
    )

    with patch("gateway.services.agentix_client.run_sim_scenario", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = {"status": "success", "run_id": "run-123"}

        response = client.post("/web/simulations/scenarios/sc-1/run?rate=2.0", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200
        data = response.json()
        assert data["run_id"] == "run-123"
        mock_run.assert_called_once_with("sc-1", 2.0, False)


@pytest.mark.asyncio
async def test_list_runs_gateway_success(client):
    token = create_access_token(
        data={"uid": "test-user-123", "email": "test-user@agentix.ai", "role": "admin", "permissions": ["read"]}
    )

    with patch("gateway.services.agentix_client.list_sim_runs", new_callable=AsyncMock) as mock_list_runs:
        mock_list_runs.return_value = [
            {"id": "run-123", "status": "COMPLETED", "total_events": 10}
        ]

        response = client.get("/web/simulations/runs?limit=5", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["id"] == "run-123"
        mock_list_runs.assert_called_once_with(5, 0)


@pytest.mark.asyncio
async def test_run_results_gateway_success(client):
    token = create_access_token(
        data={"uid": "test-user-123", "email": "test-user@agentix.ai", "role": "admin", "permissions": ["read"]}
    )

    with patch("gateway.services.agentix_client.get_sim_run_results", new_callable=AsyncMock) as mock_results:
        mock_results.return_value = {
            "run": {"id": "run-123", "status": "COMPLETED"},
            "results": [{"id": "res-1", "match_result": "CORRECT"}]
        }

        response = client.get("/web/simulations/runs/run-123/results", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200
        data = response.json()
        assert data["run"]["id"] == "run-123"
        assert len(data["results"]) == 1
        mock_results.assert_called_once_with("run-123")


@pytest.mark.asyncio
async def test_sim_stats_gateway_success(client):
    token = create_access_token(
        data={"uid": "test-user-123", "email": "test-user@agentix.ai", "role": "admin", "permissions": ["read"]}
    )

    with patch("gateway.services.agentix_client.get_sim_stats", new_callable=AsyncMock) as mock_stats:
        mock_stats.return_value = {"total_runs": 10, "matched": 9, "accuracy_rate": 90.0}

        response = client.get("/web/simulations/stats", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200
        data = response.json()
        assert data["accuracy_rate"] == 90.0
        mock_stats.assert_called_once()
