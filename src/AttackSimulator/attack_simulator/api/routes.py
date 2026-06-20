import uuid

from attack_simulator.models import db_repo
from attack_simulator.services.simulation import SimulationService
from fastapi import APIRouter, HTTPException, Path, Query
from pydantic import BaseModel, Field

router = APIRouter()
simulation_service = SimulationService()


class BulkRunRequest(BaseModel):
    name: str = Field(..., max_length=255)
    scenario_ids: list[str]
    send_rate_per_sec: float = Field(1.0, ge=0.1, le=10.0)
    strip_labels: bool = False


@router.get("/simulations/scenarios")
async def get_simulation_scenarios():
    """
    Get all available simulation scenarios.
    """
    try:
        return await db_repo.list_scenarios()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/simulations/scenarios/{scenario_id}/events")
async def get_simulation_scenario_events(scenario_id: str = Path(..., max_length=100)):
    """
    Get the event sequence preview for a scenario.
    """
    try:
        uuid.UUID(scenario_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scenario UUID format")

    try:
        return await db_repo.get_scenario_events(scenario_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/simulations/scenarios/{scenario_id}/activate")
async def activate_simulation_scenario(scenario_id: str = Path(..., max_length=100)):
    """
    Activate a scenario and deactivate all others.
    """
    try:
        uuid.UUID(scenario_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scenario UUID format")

    try:
        await db_repo.activate_scenario(scenario_id)
        return {"status": "success", "message": f"Scenario {scenario_id} activated successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/simulations/scenarios/{scenario_id}/run")
async def run_simulation_scenario(
    scenario_id: str = Path(..., max_length=100),
    send_rate_per_sec: float = Query(1.0, ge=0.1, le=10.0),
    strip_labels: bool = Query(False),
):
    """
    Trigger a simulation run for the target scenario.
    """
    try:
        sc_uuid = uuid.UUID(scenario_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scenario UUID format")

    try:
        sc = await db_repo.get_scenario_by_id(sc_uuid)
        if not sc:
            raise HTTPException(status_code=404, detail="Scenario not found")

        run_id = await simulation_service.run_simulation(
            scenario_name=sc["name"],
            delay_between_events=1.0 / send_rate_per_sec if send_rate_per_sec > 0 else 1.0,
            strip_labels=strip_labels,
        )
        return {"status": "success", "run_id": run_id, "message": "Simulation run triggered"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/simulations/runs")
async def get_simulation_runs(limit: int = Query(20, ge=1, le=100)):
    """
    Get recent simulation runs.
    """
    try:
        active_ids = await db_repo.get_active_simulation_runs()
        for r_id in active_ids:
            await simulation_service.evaluate_run_if_needed(r_id)

        return await db_repo.get_latest_runs(limit=limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/simulations/runs/{run_id}/results")
async def get_simulation_run_results(run_id: str = Path(..., max_length=100)):
    """
    Get detailed events/results for a simulation run.
    """
    try:
        uuid.UUID(run_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid run UUID format")

    try:
        await simulation_service.evaluate_run_if_needed(run_id)

        run_row = await db_repo.get_run(run_id)
        if not run_row:
            raise HTTPException(status_code=404, detail="Simulation run not found")

        results = await db_repo.get_run_results(run_id)
        return {"run": run_row, "results": results}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/simulations/stats")
async def get_simulation_stats():
    """
    Get overall simulation precision metrics.
    """
    try:
        pool = await db_repo.get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT COUNT(*)::int as total_runs,
                       COALESCE(SUM(matched_playbooks), 0)::int as matched,
                       COALESCE(SUM(mismatched_playbooks), 0)::int as mismatched,
                       COALESCE(SUM(no_playbook), 0)::int as no_playbook
                FROM simulator.simulation_runs
                """
            )
            stats = dict(row) if row else {"total_runs": 0, "matched": 0, "mismatched": 0, "no_playbook": 0}
            total_finished = stats["matched"] + stats["mismatched"] + stats["no_playbook"]
            accuracy = (stats["matched"] / total_finished * 100.0) if total_finished > 0 else 0.0
            stats["accuracy_rate"] = round(accuracy, 1)
            return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/simulations/bulk-runs")
async def trigger_bulk_simulations(payload: BulkRunRequest):
    """
    Triggers a bulk run for selected scenarios.
    """
    if not payload.scenario_ids:
        raise HTTPException(status_code=400, detail="At least one scenario ID must be provided")

    try:
        from agentic_common.settings import settings

        llm_provider = settings.agentix_llm_provider
        llm_model = (
            settings.openai_model
            if llm_provider == "openai"
            else settings.gemini_model
            if llm_provider == "gemini"
            else settings.ollama_model
        )

        bulk_run_id = await simulation_service.trigger_bulk_simulations(
            name=payload.name,
            scenario_ids=payload.scenario_ids,
            send_rate_per_sec=payload.send_rate_per_sec,
            strip_labels=payload.strip_labels,
            llm_provider=llm_provider,
            llm_model=llm_model,
        )

        return {"status": "success", "bulk_run_id": bulk_run_id, "message": "Bulk simulation run started in background"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/simulations/bulk-runs")
async def list_bulk_runs(limit: int = Query(20, ge=1, le=100)):
    """
    Get recent bulk simulation runs.
    """
    try:
        return await db_repo.get_bulk_runs(limit=limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/simulations/bulk-runs/{bulk_run_id}/results")
async def get_bulk_run_results(bulk_run_id: str = Path(..., max_length=100)):
    """
    Get detailed results for all scenario runs under a bulk run.
    """
    try:
        uuid.UUID(bulk_run_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid bulk run UUID format")

    try:
        bulk_meta = await db_repo.get_bulk_run(bulk_run_id)
        if not bulk_meta:
            raise HTTPException(status_code=404, detail="Bulk run not found")

        # Format timestamps
        for t_field in ("completed_at", "created_at"):
            if bulk_meta.get(t_field):
                bulk_meta[t_field] = bulk_meta[t_field].isoformat()

        runs = await db_repo.get_runs_for_bulk(bulk_run_id)
        for r in runs:
            for t_field in ("started_at", "completed_at", "created_at"):
                if r.get(t_field):
                    r[t_field] = r[t_field].isoformat()

        return {"bulk_run": bulk_meta, "runs": runs}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/simulations/bulk-runs/{bulk_run_id}/cancel")
async def cancel_bulk_run_endpoint(bulk_run_id: str = Path(..., max_length=100)):
    """
    Cancels a bulk run, skipping remaining scenarios.
    """
    try:
        uuid.UUID(bulk_run_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid bulk run UUID format")

    try:
        bulk_meta = await db_repo.get_bulk_run(bulk_run_id)
        if not bulk_meta:
            raise HTTPException(status_code=404, detail="Bulk run not found")

        if bulk_meta["status"] != "RUNNING":
            raise HTTPException(
                status_code=400, detail=f"Bulk run is in '{bulk_meta['status']}' state and cannot be cancelled."
            )

        await simulation_service.cancel_bulk_run(bulk_run_id)
        return {"status": "success", "message": "Bulk run cancellation processed successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/settings/llm")
async def get_active_llm_setting():
    """
    Get active LLM settings for the core Agentix platform.
    """
    from agentic_common.settings import settings

    return {
        "provider": settings.agentix_llm_provider,
        "model": (
            settings.openai_model
            if settings.agentix_llm_provider == "openai"
            else settings.gemini_model
            if settings.agentix_llm_provider == "gemini"
            else settings.ollama_model
        ),
    }
