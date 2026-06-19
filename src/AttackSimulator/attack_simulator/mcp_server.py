"""
FastMCP Server exposing AttackSimulator tools.
"""

import asyncio
import os
from typing import Literal, cast
from fastmcp import FastMCP
import structlog

from attack_simulator.models import db_repo
from attack_simulator.sender.webhook import send_alert_to_webhook
from attack_simulator.evaluator.playbook_match import evaluate_run
from attack_simulator.evaluator.gap_analyzer import generate_coverage_report, print_ascii_gap_report

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
    """
    import copy
    try:
        events = await db_repo.get_scenario_events(scenario_id)
        sent_events = 0
        
        for idx, ev in enumerate(events):
            # Send alert to Agentix webhook
            alert_payload = copy.deepcopy(ev["wazuh_alert"])
            if strip_labels:
                if "rule" in alert_payload and isinstance(alert_payload["rule"], dict):
                    alert_payload["rule"].pop("mitre", None)
                    alert_payload["rule"].pop("rule_id", None)
                    if "groups" in alert_payload["rule"] and isinstance(alert_payload["rule"]["groups"], list):
                        import re
                        alert_payload["rule"]["groups"] = [
                            g for g in alert_payload["rule"]["groups"]
                            if not (str(g).lower().startswith("mitre_") or re.match(r"^t\d{4}", str(g).lower()))
                        ]
                    alert_payload["rule"]["id"] = "999999"
                alert_payload.pop("mitre_ids", None)
                alert_payload.pop("rule_id", None)
                
            alert_payload["simulation_run_id"] = str(run_id)
            session_id = await send_alert_to_webhook(alert_payload)
            
            # Record result
            expected_mitre = [ev["mitre_technique"]]
            expected_list = []
            try:
                from triage_core.playbooks import registry as pb_registry
                candidates = pb_registry.find_for_alert(mitre_ids=expected_mitre)
                expected_list = [c.id for c in candidates]
            except Exception:
                pass
                
            expected_pb = expected_list[0] if expected_list else None
            
            await db_repo.insert_simulation_result(
                run_id=run_id,
                event_id=ev["id"],
                session_id=session_id,
                expected_mitre=expected_mitre,
                expected_playbook=expected_pb,
                match_result="PENDING",
            )
            
            sent_events += 1
            await db_repo.update_run_stats(
                run_id=run_id,
                status="RUNNING",
                sent_events=sent_events
            )
            
            if idx < len(events) - 1:
                await asyncio.sleep(delay_seconds)
                
        # Wait a few seconds for the async agent triage workflow to finish matching playbooks
        logger.info("mcp.simulation_run_worker.sleeping_for_eval", run_id=run_id)
        await asyncio.sleep(8)
        
        # Run evaluation
        await evaluate_run(run_id)
        logger.info("mcp.simulation_run_worker.completed", run_id=run_id)
        
    except Exception as e:
        logger.exception("mcp.simulation_run_worker.error", run_id=run_id, error=str(e))
        await db_repo.update_run_stats(
            run_id=run_id,
            status="FAILED",
            sent_events=0
        )


@mcp.tool()
async def trigger_attack_simulation(scenario_name: str, delay_between_events: float = 1.0, strip_labels: bool = False) -> str:
    """
    Triggers an attack simulation scenario by name.
    Sends correlated events to the SIEM webhook in the background.
    
    Args:
        scenario_name: The name of the scenario to execute (e.g. 'Credential Access Attacks').
        delay_between_events: Seconds of delay to wait between sending each alert (default: 1.0).
        strip_labels: If True, strips MITRE technique/tactic IDs and rule IDs from the alert payload (default: False).
    """
    if not scenario_name or len(scenario_name) > 255:
        return "Error: Scenario name exceeds 255 characters limit."
        
    try:
        sc = await db_repo.get_scenario_by_name(scenario_name)
        if not sc:
            return f"Scenario '{scenario_name}' not found."
            
        scenario_id = sc["id"]
        total_events = sc["total_events"]
        
        # Create new run in PENDING/RUNNING state
        rate = 1.0 / delay_between_events if delay_between_events > 0 else 1.0
        run_id = await db_repo.create_run(scenario_id, total_events, rate)
        
        # Spawn execution in background task to avoid blocking the MCP client
        asyncio.create_task(_run_simulation_task(scenario_id, run_id, delay_between_events, strip_labels=strip_labels))
        
        import json
        return json.dumps({
            "status": "RUNNING",
            "run_id": run_id,
            "message": f"Simulation started for scenario '{scenario_name}'. Executing in background.",
            "total_events": total_events
        }, indent=2)
        
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
        
    filename = os.path.basename(url)
    dest_dir = "data"
    local_path = os.path.abspath(os.path.join(dest_dir, filename))
    
    # Check if file is already downloaded
    if os.path.exists(local_path) and os.path.getsize(local_path) > 100:
        return f"Error: File '{filename}' is already downloaded. Download blocked."
        
    # Check if scenario is in database and has events
    existing_sc = await db_repo.get_scenario_by_path(url)
    if not existing_sc:
        existing_sc = await db_repo.get_scenario_by_path(local_path)
    if existing_sc:
        events = await db_repo.get_scenario_events(existing_sc["id"])
        if events:
            return f"Error: Scenario associated with '{filename}' is already ingested and has events. Download blocked."
            
    # Download
    try:
        os.makedirs(dest_dir, exist_ok=True)
        from attack_simulator.cli import download_file
        await download_file(url, local_path)
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
        if not report['uncovered_simulated']:
            lines.append("  *No gaps found! 100% coverage of simulated techniques.*")
        else:
            for item in report['uncovered_simulated']:
                lines.append(f"- **{item['technique_id']}** - {item['info']['name']} (Tactic: {item['info']['tactic']})")
                
        lines.append("\n## Covered Simulated Techniques")
        if not report['covered_simulated']:
            lines.append("  *None*")
        else:
            for item in report['covered_simulated']:
                lines.append(f"- **{item['technique_id']}** - {item['info']['name']} → Covered by: {', '.join(item['playbooks'])}")
                
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
    import glob
    import hashlib
    from attack_simulator.mapper.mordor_filename import get_mordor_file_info, extract_technique_from_path
    from attack_simulator.loader.mordor import MordorLoader
    from attack_simulator.loader.custom import CustomLoader
    from attack_simulator.correlation.engine import CorrelationEngine
    
    if not os.path.exists(directory_path):
        return f"Error: Directory '{directory_path}' does not exist."
        
    patterns = [
        os.path.join(directory_path, "*.zip"),
        os.path.join(directory_path, "*.tar.gz"),
        os.path.join(directory_path, "*.json"),
    ]
    files = []
    for pat in patterns:
        files.extend(glob.glob(pat))
        
    files = list(set(os.path.abspath(f) for f in files))
    files.sort()
    
    if not files:
        return f"No dataset files (*.zip, *.tar.gz, *.json) found in '{directory_path}'."
        
    engine = CorrelationEngine()
    skipped = 0
    ingested = 0
    failed = 0
    
    def compute_sha256(data: str) -> str:
        return hashlib.sha256(data.encode("utf-8")).hexdigest()
        
    for file_path in files:
        filename = os.path.basename(file_path)
        if os.path.getsize(file_path) < 10:
            skipped += 1
            continue
            
        existing_sc = await db_repo.get_scenario_by_path(file_path)
        if existing_sc:
            events = await db_repo.get_scenario_events(existing_sc["id"])
            if events:
                skipped += 1
                continue
                
        info = get_mordor_file_info(filename)
        if info:
            scenario_name = info.get("title") or filename
            scenario_desc = info.get("description") or f"Simulated attack using Mordor dataset: {filename}"
            mitre_ids = info.get("techniques", [])
        else:
            scenario_name = os.path.splitext(filename)[0].replace("_", " ").title()
            scenario_desc = f"Simulated attack using dataset: {filename}"
            mitre_ids = [extract_technique_from_path(file_path)]
            
        scenario_name = scenario_name[:255]
        scenario_desc = scenario_desc[:1000]
        
        existing_name = await db_repo.get_scenario_by_name(scenario_name)
        if existing_name:
            events = await db_repo.get_scenario_events(existing_name["id"])
            if events:
                skipped += 1
                continue
                
        is_mordor = filename.endswith((".zip", ".tar.gz"))
        if is_mordor:
            loader = MordorLoader()
            raw_events_gen = loader.load(file_path)
        else:
            loader_custom = CustomLoader()
            try:
                metadata, raw_events_list = loader_custom.load_scenario_file(file_path)
                if not info:
                    scenario_name = metadata.get("name", scenario_name)[:255]
                    scenario_desc = metadata.get("description", scenario_desc)[:1000]
                raw_events_gen = (e for e in raw_events_list)
            except Exception as e:
                logger.error("mcp.ingest_all.failed_to_load_custom", path=file_path, error=str(e))
                failed += 1
                continue
                
        correlated_events = []
        seq_order = 1
        
        try:
            for raw in raw_events_gen:
                alerts = engine.process_event(raw)
                for alert in alerts:
                    raw_log_str = alert.get("full_log", "")
                    raw_hash = compute_sha256(raw_log_str)
                    
                    correlated_events.append({
                        "sequence_order": seq_order,
                        "mitre_technique": alert["rule"]["mitre"]["id"][0],
                        "mitre_tactic": alert["rule"]["mitre"]["tactic"][0],
                        "correlation_type": "direct" if "aggregation" not in alert["full_log"].lower() else "aggregation",
                        "raw_event_count": 1,
                        "correlation_rule": alert["rule"]["description"],
                        "wazuh_alert": alert,
                        "raw_log_hash": raw_hash,
                    })
                    seq_order += 1
        except Exception as e:
            logger.error("mcp.ingest_all.error_correlating", filename=filename, error=str(e))
            failed += 1
            continue
            
        if not correlated_events:
            try:
                scenario_id = await db_repo.create_scenario(
                    name=scenario_name,
                    description=scenario_desc,
                    mitre_ids=mitre_ids,
                    source_dataset="mordor" if is_mordor else "custom",
                    source_path=file_path,
                    total_events=0,
                    status="passive",
                )
                ingested += 1
            except Exception as e:
                logger.error("mcp.ingest_all.db_insert_failed_empty", filename=filename, error=str(e))
                failed += 1
            continue

            
        event_techs = [ev["mitre_technique"] for ev in correlated_events]
        combined_mitre_ids = list(set(mitre_ids + event_techs))
        
        try:
            scenario_id = await db_repo.create_scenario(
                name=scenario_name,
                description=scenario_desc,
                mitre_ids=combined_mitre_ids,
                source_dataset="mordor" if is_mordor else "custom",
                source_path=file_path,
                total_events=len(correlated_events),
                status="passive",
            )
            for ev in correlated_events:
                ev["scenario_id"] = scenario_id
            await db_repo.insert_attack_events(correlated_events, status="passive")
            ingested += 1
        except Exception as e:
            logger.error("mcp.ingest_all.db_insert_failed", filename=filename, error=str(e))
            failed += 1
            
    import json
    return json.dumps({
        "status": "COMPLETED",
        "total_files": len(files),
        "ingested": ingested,
        "skipped": skipped,
        "failed": failed
    }, indent=2)


def run_server() -> None:
    """
    Starts the MCP Server using env configuration.
    """
    transport = os.getenv("FASTMCP_TRANSPORT", "stdio")
    port = int(os.getenv("FASTMCP_PORT", "8082"))
    
    transport_type = cast(Literal["stdio", "sse", "http", "streamable-http"], transport)
    logger.info("mcp_server.starting", server="AttackSimulator", transport=transport, port=port)
    
    if transport_type == "sse":
        mcp.run(transport=transport_type, port=port, host="0.0.0.0")
    else:
        mcp.run(transport=transport_type)


if __name__ == "__main__":
    run_server()

