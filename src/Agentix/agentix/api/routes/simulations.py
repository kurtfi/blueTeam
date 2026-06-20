import structlog
from fastapi import APIRouter, HTTPException, Path, Query, Request
from pydantic import BaseModel, Field

logger = structlog.get_logger(__name__)
router = APIRouter()


class BulkRunRequest(BaseModel):
    name: str = Field(..., max_length=255)
    scenario_ids: list[str]
    send_rate_per_sec: float = Field(1.0, ge=0.1, le=10.0)
    strip_labels: bool = False


@router.get("/simulations/scenarios")
async def get_simulation_scenarios(request: Request):
    """
    Get all available simulation scenarios (Proxied).
    """
    return await request.app.state.simulation_service.list_scenarios()


@router.get("/simulations/scenarios/{scenario_id}/events")
async def get_simulation_scenario_events(request: Request, scenario_id: str = Path(..., max_length=100)):
    """
    Get the event sequence preview for a scenario (Proxied).
    """
    return await request.app.state.simulation_service.get_scenario_events(scenario_id)


@router.post("/simulations/scenarios/{scenario_id}/activate")
async def activate_simulation_scenario(request: Request, scenario_id: str = Path(..., max_length=100)):
    """
    Activate a scenario and deactivate all others (Proxied).
    """
    return await request.app.state.simulation_service.activate_scenario(scenario_id)


@router.post("/simulations/scenarios/{scenario_id}/run")
async def run_simulation_scenario(
    request: Request,
    scenario_id: str = Path(..., max_length=100),
    send_rate_per_sec: float = Query(1.0, ge=0.1, le=10.0),
    strip_labels: bool = Query(False),
):
    """
    Trigger a simulation run for the target scenario (Proxied).
    """
    run_id = await request.app.state.simulation_service.trigger_simulation(
        scenario_id=scenario_id,
        send_rate_per_sec=send_rate_per_sec,
        strip_labels=strip_labels,
    )
    return {"status": "success", "run_id": run_id, "message": "Simulation run triggered"}


@router.get("/simulations/runs")
async def get_simulation_runs(request: Request, limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0)):
    """
    Get recent simulation runs (Proxied).
    """
    return await request.app.state.simulation_service.list_runs(limit=limit, offset=offset)


@router.get("/simulations/runs/{run_id}/results")
async def get_simulation_run_results(request: Request, run_id: str = Path(..., max_length=100)):
    """
    Get detailed events/results for a simulation run (Proxied).
    """
    return await request.app.state.simulation_service.get_run_results(run_id)


@router.get("/simulations/stats")
async def get_simulation_stats(request: Request):
    """
    Get overall simulation precision metrics (Proxied).
    """
    return await request.app.state.simulation_service.get_stats()


@router.post("/simulations/bulk-runs")
async def trigger_bulk_simulations(request: Request, payload: BulkRunRequest):
    """
    Triggers a bulk run for selected scenarios (Proxied).
    """
    if not payload.scenario_ids:
        raise HTTPException(status_code=400, detail="At least one scenario ID must be provided")

    bulk_run_id = await request.app.state.simulation_service.trigger_bulk_simulations(
        name=payload.name,
        scenario_ids=payload.scenario_ids,
        send_rate_per_sec=payload.send_rate_per_sec,
        strip_labels=payload.strip_labels,
    )
    return {"status": "success", "bulk_run_id": bulk_run_id, "message": "Bulk simulation run started in background"}


@router.get("/simulations/bulk-runs")
async def list_bulk_runs(request: Request, limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0)):
    """
    Get recent bulk simulation runs (Proxied).
    """
    return await request.app.state.simulation_service.list_bulk_runs(limit=limit, offset=offset)


@router.get("/simulations/bulk-runs/{bulk_run_id}/results")
async def get_bulk_run_results(request: Request, bulk_run_id: str = Path(..., max_length=100)):
    """
    Get detailed results for all scenario runs under a bulk run (Proxied).
    """
    return await request.app.state.simulation_service.get_bulk_run_results(bulk_run_id)


@router.post("/simulations/bulk-runs/{bulk_run_id}/cancel")
async def cancel_bulk_run_endpoint(request: Request, bulk_run_id: str = Path(..., max_length=100)):
    """
    Cancels a bulk run, skipping remaining scenarios (Proxied).
    """
    await request.app.state.simulation_service.cancel_bulk_run(bulk_run_id)
    return {"status": "success", "message": "Bulk run cancellation processed successfully"}


@router.get("/settings/llm")
async def get_active_llm_setting(request: Request):
    """
    Get active LLM settings for the core Agentix platform (Proxied via AttackSimulator API).
    """
    # We call settings endpoint from AttackSimulator to keep it consistent
    return await request.app.state.simulation_service._request("GET", "/settings/llm")
