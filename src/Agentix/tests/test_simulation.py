import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import HTTPException
from agentix.services.simulation import SimulationService


@pytest.fixture
def service():
    return SimulationService(api_url="http://mock-simulator:8083")


@pytest.mark.asyncio
async def test_proxy_list_scenarios(service):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = [{"id": "sc-1", "name": "Scenario 1"}]

    with patch("httpx.AsyncClient.request", new_callable=AsyncMock) as mock_request:
        mock_request.return_value = mock_resp
        scenarios = await service.list_scenarios()
        assert len(scenarios) == 1
        assert scenarios[0]["name"] == "Scenario 1"
        mock_request.assert_called_once_with(
            "GET", "http://mock-simulator:8083/v1/simulations/scenarios", params=None, json=None
        )


@pytest.mark.asyncio
async def test_proxy_get_scenario_events(service):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = [{"id": "event-1", "sequence_order": 1}]

    with patch("httpx.AsyncClient.request", new_callable=AsyncMock) as mock_request:
        mock_request.return_value = mock_resp
        events = await service.get_scenario_events("sc-1")
        assert len(events) == 1
        assert events[0]["sequence_order"] == 1
        mock_request.assert_called_once_with(
            "GET", "http://mock-simulator:8083/v1/simulations/scenarios/sc-1/events", params=None, json=None
        )


@pytest.mark.asyncio
async def test_proxy_activate_scenario(service):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"status": "success"}

    with patch("httpx.AsyncClient.request", new_callable=AsyncMock) as mock_request:
        mock_request.return_value = mock_resp
        res = await service.activate_scenario("sc-1")
        assert res["status"] == "success"
        mock_request.assert_called_once_with(
            "POST", "http://mock-simulator:8083/v1/simulations/scenarios/sc-1/activate", params=None, json=None
        )


@pytest.mark.asyncio
async def test_proxy_trigger_simulation(service):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"status": "success", "run_id": "run-123"}

    with patch("httpx.AsyncClient.request", new_callable=AsyncMock) as mock_request:
        mock_request.return_value = mock_resp
        run_id = await service.trigger_simulation("sc-1", send_rate_per_sec=1.0, strip_labels=False)
        assert run_id == "run-123"
        mock_request.assert_called_once_with(
            "POST",
            "http://mock-simulator:8083/v1/simulations/scenarios/sc-1/run",
            params={"send_rate_per_sec": 1.0, "strip_labels": False},
            json=None,
        )


@pytest.mark.asyncio
async def test_proxy_list_runs(service):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = [{"id": "run-123", "status": "COMPLETED"}]

    with patch("httpx.AsyncClient.request", new_callable=AsyncMock) as mock_request:
        mock_request.return_value = mock_resp
        runs = await service.list_runs(limit=10)
        assert len(runs) == 1
        assert runs[0]["id"] == "run-123"
        mock_request.assert_called_once_with(
            "GET", "http://mock-simulator:8083/v1/simulations/runs", params={"limit": 10}, json=None
        )


@pytest.mark.asyncio
async def test_proxy_get_run_results(service):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"run": {"id": "run-123"}, "results": []}

    with patch("httpx.AsyncClient.request", new_callable=AsyncMock) as mock_request:
        mock_request.return_value = mock_resp
        res = await service.get_run_results("run-123")
        assert res["run"]["id"] == "run-123"
        mock_request.assert_called_once_with(
            "GET", "http://mock-simulator:8083/v1/simulations/runs/run-123/results", params=None, json=None
        )


@pytest.mark.asyncio
async def test_proxy_get_stats(service):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"total_runs": 10, "accuracy_rate": 80.0}

    with patch("httpx.AsyncClient.request", new_callable=AsyncMock) as mock_request:
        mock_request.return_value = mock_resp
        stats = await service.get_stats()
        assert stats["total_runs"] == 10
        assert stats["accuracy_rate"] == 80.0
        mock_request.assert_called_once_with(
            "GET", "http://mock-simulator:8083/v1/simulations/stats", params=None, json=None
        )


@pytest.mark.asyncio
async def test_proxy_trigger_bulk_simulations(service):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"status": "success", "bulk_run_id": "bulk-123"}

    with patch("httpx.AsyncClient.request", new_callable=AsyncMock) as mock_request:
        mock_request.return_value = mock_resp
        bulk_run_id = await service.trigger_bulk_simulations(
            name="Bulk 1", scenario_ids=["sc-1", "sc-2"], send_rate_per_sec=2.0, strip_labels=True
        )
        assert bulk_run_id == "bulk-123"
        mock_request.assert_called_once_with(
            "POST",
            "http://mock-simulator:8083/v1/simulations/bulk-runs",
            params=None,
            json={"name": "Bulk 1", "scenario_ids": ["sc-1", "sc-2"], "send_rate_per_sec": 2.0, "strip_labels": True},
        )


@pytest.mark.asyncio
async def test_proxy_cancel_bulk_run(service):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"status": "success"}

    with patch("httpx.AsyncClient.request", new_callable=AsyncMock) as mock_request:
        mock_request.return_value = mock_resp
        await service.cancel_bulk_run("bulk-123")
        mock_request.assert_called_once_with(
            "POST", "http://mock-simulator:8083/v1/simulations/bulk-runs/bulk-123/cancel", params=None, json=None
        )


@pytest.mark.asyncio
async def test_proxy_http_error(service):
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.text = "Internal Server Error"
    mock_resp.json.return_value = {"detail": "Internal error detail"}

    with patch("httpx.AsyncClient.request", new_callable=AsyncMock) as mock_request:
        mock_request.return_value = mock_resp
        with pytest.raises(HTTPException) as exc_info:
            await service.list_scenarios()
        assert exc_info.value.status_code == 500
        assert exc_info.value.detail == "Internal error detail"
