import uuid

from attack_simulator.repository import db_repo
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
    timing_mode: str = "constant"
    max_original_delay: float = 30.0
    sender_type: str = "webhook"


class ScenarioEventCreate(BaseModel):
    sequence_order: int
    mitre_technique: str
    mitre_tactic: str | None = None
    correlation_type: str = "direct"
    raw_event_count: int = 1
    correlation_rule: str | None = None
    wazuh_alert: dict
    raw_log_hash: str | None = None


class LinearScenarioCreate(BaseModel):
    name: str = Field(..., max_length=255)
    description: str | None = Field(None, max_length=1000)
    mitre_ids: list[str]
    source_dataset: str = Field(..., max_length=100)
    source_path: str = Field(..., max_length=1000)
    events: list[ScenarioEventCreate]


class DagScenarioCreate(BaseModel):
    name: str = Field(..., max_length=255)
    description: str | None = Field(None, max_length=1000)
    mitre_ids: list[str]
    source_dataset: str = Field(..., max_length=100)
    source_path: str = Field(..., max_length=1000)
    total_events: int = 0
    dag_structure: dict


@router.post("/simulations/scenarios/linear")
async def create_linear_scenario(payload: LinearScenarioCreate):
    """
    Ingest a new linear scenario along with its pre-correlated events.
    """
    try:
        # Check if already exists
        existing = await db_repo.get_scenario_by_name(payload.name)
        if existing:
            # Delete to recreate (matches the loader's behavior of clean seeding)
            await db_repo.delete_scenario(existing["id"])

        # Create scenario record
        scenario_id = await db_repo.create_scenario(
            name=payload.name,
            description=payload.description,
            mitre_ids=payload.mitre_ids,
            source_dataset=payload.source_dataset,
            source_path=payload.source_path,
            total_events=len(payload.events),
            status="passive",
            type="linear",
        )

        # Insert events
        db_events = []
        for ev in payload.events:
            db_ev = ev.dict()
            db_ev["scenario_id"] = scenario_id
            db_events.append(db_ev)

        await db_repo.insert_attack_events(db_events, status="passive")

        return {
            "status": "success",
            "scenario_id": scenario_id,
            "total_events": len(db_events),
            "message": f"Linear scenario '{payload.name}' ingested successfully."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/simulations/scenarios/dag")
async def create_dag_scenario(payload: DagScenarioCreate):
    """
    Ingest a new DAG scenario with its dynamic state structure.
    """
    try:
        # Check if already exists
        existing = await db_repo.get_scenario_by_name(payload.name)
        if existing:
            await db_repo.delete_scenario(existing["id"])

        scenario_id = await db_repo.create_scenario(
            name=payload.name,
            description=payload.description,
            mitre_ids=payload.mitre_ids,
            source_dataset=payload.source_dataset,
            source_path=payload.source_path,
            total_events=payload.total_events,
            status="passive",
            type="dag",
            dag_structure=payload.dag_structure,
        )

        return {
            "status": "success",
            "scenario_id": scenario_id,
            "message": f"DAG scenario '{payload.name}' ingested successfully."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



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
        sc_uuid = uuid.UUID(scenario_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scenario UUID format")

    try:
        sc = await db_repo.get_scenario_by_id(sc_uuid)
        if not sc:
            raise HTTPException(status_code=404, detail="Scenario not found")

        if sc.get("type") == "dag":
            # For DAG scenarios, flatten and return alerts from all steps as a preview sequence
            dag_struct = sc.get("dag_structure") or {}
            steps = dag_struct.get("steps", {})
            flattened_events = []
            order = 1
            for step_key, step_info in steps.items():
                wazuh_alerts = step_info.get("wazuh_alerts", [])
                for alert in wazuh_alerts:
                    flattened_events.append({
                        "id": f"dag-{step_key}-{order}",
                        "scenario_id": scenario_id,
                        "sequence_order": order,
                        "mitre_technique": step_info.get("mitre_technique"),
                        "mitre_tactic": "Multi-stage Execution",
                        "wazuh_alert": alert,
                    })
                    order += 1
            return flattened_events

        return await db_repo.get_scenario_events(scenario_id)
    except HTTPException:
        raise
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
    timing_mode: str = Query("constant"),
    max_original_delay: float = Query(30.0),
    sender_type: str = Query("webhook"),
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
            timing_mode=timing_mode,
            max_original_delay=max_original_delay,
            sender_type=sender_type,
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
            timing_mode=payload.timing_mode,
            max_original_delay=payload.max_original_delay,
            sender_type=payload.sender_type,
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
