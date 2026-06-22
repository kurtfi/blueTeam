"""
FastMCP Server exposing AttackSimulator tools.
"""

import asyncio
import os
from typing import Literal, cast

import structlog
from fastmcp import FastMCP

from attack_simulator.evaluator.gap_analyzer import generate_coverage_report
from attack_simulator.evaluator.playbook_match import evaluate_run
from attack_simulator.models import db_repo

logger = structlog.get_logger(__name__)

# Initialize FastMCP Server
mcp = FastMCP("Attack Simulator")


@mcp.tool()
async def list_simulation_scenarios() -> str:
    """
    Lists all available attack simulation scenarios ingested in the database.
    """
    try:
        scenarios = await db_repo.list_scenarios()
        if not scenarios:
            return "No scenarios found in the database. Ingest some first."

        lines = ["# Available Attack Simulation Scenarios\n"]
        for sc in scenarios:
            status_str = sc.get("status", "passive").upper()
            lines.append(
                f"- **{sc['name']}** (ID: `{sc['id']}`) [{status_str}]\n"
                f"  Description: {sc['description'] or 'No description'}\n"
                f"  MITRE Techniques: {', '.join(sc['mitre_ids'] or [])}\n"
                f"  Dataset Source: {sc['source_dataset']} | Total Correlated Events: {sc['total_events']}\n"
            )
        return "\n".join(lines)
    except Exception as e:
        logger.error("mcp.list_scenarios.error", error=str(e))
        return f"Error listing scenarios: {str(e)}"


async def _run_simulation_task(scenario_id: str, run_id: str, delay_seconds: float, strip_labels: bool = False) -> None:
    """
    Background worker that sends scenario events to the SIEM webhook.
    Delegates to SimulationService for backwards compatibility.
    """
    from attack_simulator.services.simulation import SimulationService

    service = SimulationService()
    try:
        events = await db_repo.get_scenario_events(scenario_id)
        await service.execute_simulation(
            run_id=run_id,
            scenario_id=scenario_id,
            events=events,
            delay_between_events=delay_seconds,
            strip_labels=strip_labels,
        )
    except Exception as e:
        logger.exception("mcp.simulation_run_worker.error", run_id=run_id, error=str(e))
        await db_repo.update_run_stats(run_id=run_id, status="FAILED", sent_events=0)
@mcp.tool()
async def trigger_attack_simulation(
    scenario_name: str,
    delay_between_events: float = 1.0,
    strip_labels: bool = False,
    sender_type: str = "webhook",
    timing_mode: str = "constant",
    max_original_delay: float = 30.0,
) -> str:
    """
    Triggers an attack simulation scenario by name.
    Sends correlated events to the SIEM webhook or other configured sender in the background.

    Args:
        scenario_name: The name of the scenario to execute (e.g. 'Credential Access Attacks').
        delay_between_events: Seconds of delay to wait between sending each alert (default: 1.0).
        strip_labels: If True, strips MITRE technique/tactic IDs and rule IDs from the alert payload (default: False).
        sender_type: Sender backend to use ('webhook', 'syslog', 'file', default: 'webhook').
        timing_mode: Replay timing strategy ('constant' or 'original', default: 'constant').
        max_original_delay: Maximum delay in seconds for original timing (default: 30.0).
    """
    if not scenario_name or len(scenario_name) > 255:
        return "Error: Scenario name exceeds 255 characters limit."

    try:
        from attack_simulator.services.simulation import SimulationService

        service = SimulationService()

        sc = await db_repo.get_scenario_by_name(scenario_name)
        if not sc:
            return f"Scenario '{scenario_name}' not found."

        run_id = await service.run_simulation(
            scenario_name=scenario_name,
            delay_between_events=delay_between_events,
            strip_labels=strip_labels,
            sender_type=sender_type,
            timing_mode=timing_mode,
            max_original_delay=max_original_delay,
        )

        import json

        return json.dumps(
            {
                "status": "RUNNING",
                "run_id": run_id,
                "message": f"Simulation started for scenario '{scenario_name}'. Executing in background.",
                "total_events": sc["total_events"],
            },
            indent=2,
        )

    except Exception as e:
        logger.error("mcp.trigger_simulation.error", error=str(e))
        return f"Error triggering simulation: {str(e)}"


@mcp.tool()
async def get_simulation_run_status(run_id: str) -> str:
    """
    Gets the current status and statistics of a simulation run by its ID.

    Args:
        run_id: The run UUID to retrieve status for.
    """
    if not run_id or len(run_id) > 100:
        return "Error: Run ID exceeds 100 characters limit."

    try:
        # Evaluate run first to fetch latest results
        await evaluate_run(run_id)

        run_data = await db_repo.get_run(run_id)
        if not run_data:
            return f"Simulation run ID '{run_id}' not found."

        import json

        return json.dumps(run_data, indent=2, default=str)
    except Exception as e:
        logger.error("mcp.get_status.error", run_id=run_id, error=str(e))
        return f"Error retrieving status: {str(e)}"


@mcp.tool()
async def activate_scenario(scenario_name: str) -> str:
    """
    Activates the specified attack simulation scenario by name and sets all other scenarios to passive.

    Args:
        scenario_name: The name of the scenario to activate (e.g. 'Credential Access Attacks').
    """
    if not scenario_name or len(scenario_name) > 255:
        return "Error: Scenario name exceeds 255 characters limit."
    try:
        sc = await db_repo.get_scenario_by_name(scenario_name)
        if not sc:
            return f"Error: Scenario '{scenario_name}' not found."

        await db_repo.activate_scenario(sc["id"])
        return f"Scenario '{scenario_name}' has been activated. All other scenarios are now set to passive."
    except Exception as e:
        logger.error("mcp.activate_scenario.error", error=str(e))
        return f"Error activating scenario: {str(e)}"


@mcp.tool()
async def download_mordor_scenario(url: str) -> str:
    """
    Downloads a Mordor dataset zip file from a URL to the local data/ folder.
    Performs duplicate checks to block downloading if already downloaded or ingested.

    Args:
        url: The HTTP/HTTPS URL of the Mordor dataset zip file to download.
    """
    if not url or len(url) > 1000:
        return "Error: URL exceeds 1000 characters limit."

    try:
        from attack_simulator.services.ingestion import IngestionService

        service = IngestionService()
        local_path = await service.download_dataset(url)
        return f"Successfully downloaded dataset from {url} to {local_path}"
    except Exception as e:
        logger.error("mcp.download_scenario.error", error=str(e))
        return f"Error downloading dataset: {str(e)}"


@mcp.tool()
async def get_playbook_coverage_gaps() -> str:
    """
    Generates a coverage gap report comparing simulated techniques against registered playbooks.
    """
    try:
        report = await generate_coverage_report()

        lines = ["# Playbook Coverage Gap Report\n"]
        lines.append(f"- **Total Registered Playbooks:** {report['total_playbooks']}")
        lines.append(f"- **Simulated Techniques:** {report['simulated_count']}")

        lines.append("\n## Uncovered Simulated Techniques (GAPS)")
        if not report["uncovered_simulated"]:
            lines.append("  *No gaps found! 100% coverage of simulated techniques.*")
        else:
            for item in report["uncovered_simulated"]:
                lines.append(
                    f"- **{item['technique_id']}** - {item['info']['name']} (Tactic: {item['info']['tactic']})"
                )

        lines.append("\n## Covered Simulated Techniques")
        if not report["covered_simulated"]:
            lines.append("  *None*")
        else:
            for item in report["covered_simulated"]:
                lines.append(
                    f"- **{item['technique_id']}** - {item['info']['name']} → Covered by: {', '.join(item['playbooks'])}"
                )

        return "\n".join(lines)
    except Exception as e:
        logger.error("mcp.gap_report.error", error=str(e))
        return f"Error generating gap report: {str(e)}"


@mcp.tool()
async def ingest_all_scenarios(directory_path: str = "data") -> str:
    """
    Ingests all dataset files in the specified directory using the compiled metadata mappings.
    Checks and prevents duplicate scenario names/paths from being ingested.

    Args:
        directory_path: Absolute or relative path to the directory containing datasets (default: 'data').
    """
    try:
        from attack_simulator.services.ingestion import IngestionService

        service = IngestionService()
        results = await service.ingest_all_scenarios(directory_path)

        import json

        return json.dumps(
            {
                "status": "COMPLETED",
                "total_files": results["total"],
                "ingested": results["ingested"],
                "skipped": results["skipped"],
                "failed": results["failed"],
            },
            indent=2,
        )
    except Exception as e:
        logger.error("mcp.ingest_all.error", error=str(e))
        return f"Error ingesting scenarios: {str(e)}"


def run_server() -> None:
    """
    Starts the MCP Server and Standalone REST API using env configuration.
    """
    transport = os.getenv("FASTMCP_TRANSPORT", "stdio")
    port = int(os.getenv("FASTMCP_PORT", "8082"))
    api_port = int(os.getenv("API_PORT", "8083"))

    transport_type = cast(Literal["stdio", "sse", "http", "streamable-http"], transport)

    if transport_type == "sse":
        import uvicorn

        from attack_simulator.api.server import app as fastapi_app

        logger.info("mcp_server.starting_dual_mode", port_mcp=port, port_api=api_port)

        mcp_app = mcp.http_app(transport="sse")

        config_mcp = uvicorn.Config(mcp_app, host="0.0.0.0", port=port, log_level="info", loop="asyncio")
        server_mcp = uvicorn.Server(config_mcp)

        config_api = uvicorn.Config(fastapi_app, host="0.0.0.0", port=api_port, log_level="info", loop="asyncio")
        server_api = uvicorn.Server(config_api)

        async def run_both():
            async with mcp._lifespan_manager():
                await asyncio.gather(server_mcp.serve(), server_api.serve())

        asyncio.run(run_both())
    else:
        logger.info("mcp_server.starting", server="AttackSimulator", transport=transport)
        mcp.run(transport=transport_type)


if __name__ == "__main__":
    run_server()
