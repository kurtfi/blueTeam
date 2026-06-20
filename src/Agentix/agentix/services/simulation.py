"""
SimulationService — HTTP Proxy client for forwarding requests to the standalone AttackSimulator service.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog
from fastapi import HTTPException

from agentic_common.settings import settings

logger = structlog.get_logger(__name__)


class SimulationService:
    """
    Client proxy for Standalone AttackSimulator service.
    Fulfills the same contract by forwarding HTTP REST API calls.
    """

    def __init__(self, api_url: str | None = None) -> None:
        self.base_url = (api_url or settings.agentix_attack_simulator_api_url).rstrip("/")

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict | None = None,
        json: dict | None = None,
    ) -> Any:
        url = f"{self.base_url}/v1{path}"
        logger.debug("simulation_service.proxy_request", method=method, url=url, params=params, json=json)
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.request(method, url, params=params, json=json)
                if resp.status_code >= 400:
                    logger.error("simulation_service.proxy_error", status_code=resp.status_code, body=resp.text)
                    raise HTTPException(status_code=resp.status_code, detail=resp.json().get("detail", resp.text))
                return resp.json()
        except httpx.RequestError as e:
            logger.exception("simulation_service.network_error", url=url)
            raise HTTPException(status_code=502, detail=f"Failed to communicate with AttackSimulator service: {str(e)}")

    async def list_scenarios(self) -> list[dict]:
        return await self._request("GET", "/simulations/scenarios")

    async def get_scenario_events(self, scenario_id: str) -> list[dict]:
        return await self._request("GET", f"/simulations/scenarios/{scenario_id}/events")

    async def activate_scenario(self, scenario_id: str) -> dict:
        return await self._request("POST", f"/simulations/scenarios/{scenario_id}/activate")

    async def trigger_simulation(
        self,
        scenario_id: str,
        send_rate_per_sec: float,
        strip_labels: bool,
        attack_simulator_session: Any = None,  # Kept for compatibility with test mock calls
        bulk_run_id: str | None = None,
    ) -> str:
        # We perform direct HTTP REST post, matching original return value of trigger_simulation
        params = {"send_rate_per_sec": send_rate_per_sec, "strip_labels": strip_labels}
        res: dict[str, Any] = await self._request("POST", f"/simulations/scenarios/{scenario_id}/run", params=params)
        return str(res["run_id"])

    async def evaluate_run_if_needed(self, run_id: str) -> None:
        # No-op in Agentix core as evaluation is triggered in AttackSimulator REST app when querying results.
        pass

    async def list_runs(self, limit: int = 20, offset: int = 0) -> list[dict]:
        # REST API doesn't use offset yet, but we pass limit
        return await self._request("GET", "/simulations/runs", params={"limit": limit})

    async def get_run_results(self, run_id: str) -> dict:
        return await self._request("GET", f"/simulations/runs/{run_id}/results")

    async def get_stats(self) -> dict:
        return await self._request("GET", "/simulations/stats")

    async def trigger_bulk_simulations(
        self,
        name: str,
        scenario_ids: list[str],
        send_rate_per_sec: float,
        strip_labels: bool,
        llm_provider: str | None = None,
        llm_model: str | None = None,
    ) -> str:
        payload = {
            "name": name,
            "scenario_ids": scenario_ids,
            "send_rate_per_sec": send_rate_per_sec,
            "strip_labels": strip_labels,
        }
        res: dict[str, Any] = await self._request("POST", "/simulations/bulk-runs", json=payload)
        return str(res["bulk_run_id"])

    async def list_bulk_runs(self, limit: int = 20, offset: int = 0) -> list[dict]:
        return await self._request("GET", "/simulations/bulk-runs", params={"limit": limit})

    async def get_bulk_run_results(self, bulk_run_id: str) -> dict:
        return await self._request("GET", f"/simulations/bulk-runs/{bulk_run_id}/results")

    async def cancel_bulk_run(self, bulk_run_id: str) -> None:
        await self._request("POST", f"/simulations/bulk-runs/{bulk_run_id}/cancel")
