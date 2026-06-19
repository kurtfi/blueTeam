"""
CLI entry point for AttackSimulator.
"""

import argparse
import asyncio
import os
import sys
import hashlib
from typing import Any

from tqdm import tqdm  # type: ignore[import-untyped]
import structlog

from attack_simulator.models import db_repo
from attack_simulator.loader.mordor import MordorLoader
from attack_simulator.loader.custom import CustomLoader
from attack_simulator.correlation.engine import CorrelationEngine
from attack_simulator.sender.webhook import send_alert_to_webhook
from attack_simulator.evaluator.playbook_match import evaluate_run
from attack_simulator.evaluator.gap_analyzer import generate_coverage_report, print_ascii_gap_report
from attack_simulator.config import WEBHOOK_URL

logger = structlog.get_logger(__name__)


def compute_sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def correlate_and_fallback_events(
    raw_events_gen, 
    mitre_ids: list[str], 
    engine: CorrelationEngine
) -> list[dict[str, Any]]:
    """
    Correlates raw events with rules and filters alerts not matching the scenario's techniques.
    Generates fallback alerts for execution events if no rules match.
    """
    from attack_simulator.mapper.wazuh_template import generate_wazuh_alert
    from attack_simulator.mapper.mitre_catalog import get_mitre_info
    
    correlated_events = []
    seq_order = 1
    primary_technique = mitre_ids[0] if mitre_ids else "T1059"
    
    # Normalize mitre_ids to facilitate easy checking
    normalized_mitre_ids = {m.upper().strip() for m in mitre_ids}
    # Also add parent technique IDs for sub-techniques (e.g. T1003 for T1003.001)
    parent_ids = set()
    for m in normalized_mitre_ids:
        if "." in m:
            parent_ids.add(m.split(".")[0])
    normalized_mitre_ids.update(parent_ids)
    
    first_few_events = []
    
    for raw in raw_events_gen:
        # Keep track of first few events for fail-safe fallback
        if len(first_few_events) < 3:
            first_few_events.append(raw)
            
        alerts = engine.process_event(raw)
        matched_any = False
        
        # 1. Standard rules processing
        for alert in alerts:
            alert_tech = alert["rule"]["mitre"]["id"][0].upper().strip()
            # ONLY ingest standard correlated alerts if they belong to this scenario's techniques.
            # This filters out background noise (like LSASS access Event ID 10) in unrelated scenarios.
            if alert_tech in normalized_mitre_ids:
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
                matched_any = True
                
        # 2. Fallback processing:
        # If no explicit rules matched this event, check if it is a relevant execution/action event
        if not matched_any:
            event_id = str(raw.get("EventID") or raw.get("event_id") or raw.get("eventID") or "")
            command_line = raw.get("CommandLine") or raw.get("message") or ""
            
            is_execution = (
                event_id in ("1", "3", "11", "12", "13", "4104", "4662", "4688", "7045", "5156") 
                or bool(command_line)
            )
            
            if is_execution:
                alert = generate_wazuh_alert(primary_technique, raw)
                raw_log_str = alert.get("full_log", "")
                raw_hash = compute_sha256(raw_log_str)
                
                mitre_info = get_mitre_info(primary_technique)
                
                correlated_events.append({
                    "sequence_order": seq_order,
                    "mitre_technique": primary_technique,
                    "mitre_tactic": mitre_info.get("tactic", "Unknown Tactic"),
                    "correlation_type": "direct",
                    "raw_event_count": 1,
                    "correlation_rule": f"Fallback alert for {primary_technique} execution",
                    "wazuh_alert": alert,
                    "raw_log_hash": raw_hash,
                })
                seq_order += 1
                
    # 3. Fail-safe fallback if 0 events matched
    if not correlated_events and first_few_events:
        logger.info("correlate_and_fallback.failsafe_triggered", mitre_ids=mitre_ids)
        for raw in first_few_events:
            alert = generate_wazuh_alert(primary_technique, raw)
            raw_log_str = alert.get("full_log", "")
            raw_hash = compute_sha256(raw_log_str)
            
            mitre_info = get_mitre_info(primary_technique)
            
            correlated_events.append({
                "sequence_order": seq_order,
                "mitre_technique": primary_technique,
                "mitre_tactic": mitre_info.get("tactic", "Unknown Tactic"),
                "correlation_type": "direct",
                "raw_event_count": 1,
                "correlation_rule": f"Fallback alert for {primary_technique} execution (failsafe)",
                "wazuh_alert": alert,
                "raw_log_hash": raw_hash,
            })
            seq_order += 1
            
    return correlated_events


async def download_file(url: str, dest_path: str) -> None:
    import httpx
    print(f"[*] Downloading dataset from {url} ...")
    async with httpx.AsyncClient(follow_redirects=True, timeout=60.0) as client:
        response = await client.get(url)
        if response.status_code != 200:
            raise Exception(f"HTTP Status {response.status_code}")
        with open(dest_path, "wb") as f:
            f.write(response.content)
    print(f"[+] Download complete: {dest_path} ({len(response.content)} bytes)")


async def download_command(args: argparse.Namespace) -> None:
    """Downloads a dataset from a URL to data/ directory with duplication checks."""
    url = args.url
    if len(url) > 1000:
        print("[-] Error: URL exceeds 1000 characters limit.", file=sys.stderr)
        return
        
    filename = os.path.basename(url)
    dest_dir = "data"
    local_path = os.path.abspath(os.path.join(dest_dir, filename))
    
    # Check if file is already downloaded
    if os.path.exists(local_path) and os.path.getsize(local_path) > 100:
        print(f"[-] Error: File '{filename}' is already downloaded. Download blocked.", file=sys.stderr)
        return
        
    # Check if scenario is in database and has events
    existing_sc = await db_repo.get_scenario_by_path(url)
    if not existing_sc:
        existing_sc = await db_repo.get_scenario_by_path(local_path)
    if existing_sc:
        events = await db_repo.get_scenario_events(existing_sc["id"])
        if events:
            print(f"[-] Error: Scenario associated with '{filename}' is already ingested and has events. Download blocked.", file=sys.stderr)
            return
            
    # Download
    try:
        os.makedirs(dest_dir, exist_ok=True)
        await download_file(url, local_path)
    except Exception as e:
        print(f"[-] Error downloading dataset: {e}", file=sys.stderr)
        return


async def ingest_command(args: argparse.Namespace) -> None:
    """Ingests raw attack telemetry, correlates events, and stores scenario metadata."""
    if args.scenario_name and len(args.scenario_name) > 255:
        print("[-] Error: Scenario name exceeds 255 characters limit.", file=sys.stderr)
        return
    if args.description and len(args.description) > 1000:
        print("[-] Error: Description exceeds 1000 characters limit.", file=sys.stderr)
        return
    if len(args.path) > 1000:
        print("[-] Error: Path/URL exceeds 1000 characters limit.", file=sys.stderr)
        return

    is_url = args.path.startswith("http://") or args.path.startswith("https://")
    filename = os.path.basename(args.path)
    dest_dir = "data"
    local_path = os.path.abspath(os.path.join(dest_dir, filename)) if is_url else os.path.abspath(args.path)

    # Check 1: If file is already downloaded
    if is_url and os.path.exists(local_path) and os.path.getsize(local_path) > 100:
        print(f"[-] Error: File '{filename}' is already downloaded. Download/Ingestion blocked.", file=sys.stderr)
        return

    # Check 2: If scenario already exists in database and has events
    existing_sc = await db_repo.get_scenario_by_path(args.path)
    if not existing_sc and is_url:
        existing_sc = await db_repo.get_scenario_by_path(local_path)
    if not existing_sc:
        fallback_name = args.scenario_name or os.path.splitext(os.path.basename(local_path))[0].replace("_", " ").title()
        existing_sc = await db_repo.get_scenario_by_name(fallback_name)

    if existing_sc:
        events = await db_repo.get_scenario_events(existing_sc["id"])
        if events:
            print(f"[-] Error: Scenario '{existing_sc['name']}' is already ingested and has events in the database. Download/Ingestion blocked.", file=sys.stderr)
            return

    # If is_url, download it first
    if is_url:
        try:
            os.makedirs(dest_dir, exist_ok=True)
            await download_file(args.path, local_path)
        except Exception as e:
            print(f"[-] Error downloading dataset: {e}", file=sys.stderr)
            return
        source_path = local_path
    else:
        source_path = local_path

    if not os.path.exists(source_path):
        print(f"[-] Error: Source path does not exist: {source_path}", file=sys.stderr)
        return

    print(f"[*] Starting ingestion from {args.source} source: {args.path} ...")
    
    # 1. Initialize loader and resolve mitre_ids
    from attack_simulator.mapper.mordor_filename import get_mordor_file_info, extract_technique_from_path
    if args.source == "mordor":
        loader = MordorLoader()
        # Fallback names
        scenario_name = args.scenario_name or os.path.splitext(os.path.basename(source_path))[0].replace("_", " ").title()
        scenario_desc = args.description or f"Simulated attack using Mordor dataset: {os.path.basename(source_path)}"
        
        # Check name to block duplicate scenario names
        existing_name = await db_repo.get_scenario_by_name(scenario_name)
        if existing_name:
            print(f"[-] Error: Scenario with name '{scenario_name}' is already ingested. Ingestion blocked.", file=sys.stderr)
            return

        info = get_mordor_file_info(os.path.basename(source_path))
        if info:
            mitre_ids = info.get("techniques", [])
        else:
            mitre_ids = [extract_technique_from_path(source_path)]

        raw_events_gen = loader.load(source_path)
    else:  # custom
        loader_custom = CustomLoader()
        try:
            metadata, raw_events_list = loader_custom.load_scenario_file(source_path)
            scenario_name = args.scenario_name or metadata["name"]
            scenario_desc = args.description or metadata["description"]
            mitre_ids = metadata.get("mitre_ids", [])
            
            # Check name to block duplicate scenario names
            existing_name = await db_repo.get_scenario_by_name(scenario_name)
            if existing_name:
                print(f"[-] Error: Scenario with name '{scenario_name}' is already ingested. Ingestion blocked.", file=sys.stderr)
                return

            raw_events_gen = (e for e in raw_events_list)
        except Exception as e:
            print(f"[-] Error loading custom scenario file: {e}", file=sys.stderr)
            return

    # 2. Correlate raw events on-the-fly
    engine = CorrelationEngine()
    
    raw_count = 0
    def count_raw_generator(gen):
        nonlocal raw_count
        for item in gen:
            raw_count += 1
            yield item

    print("[*] Processing raw events and running correlation engine with fallback...")
    correlated_events = correlate_and_fallback_events(count_raw_generator(raw_events_gen), mitre_ids, engine)

    if not correlated_events:
        print("[-] Ingestion cancelled: 0 alerts generated from this raw data.")
        return

    # Extract all unique MITRE IDs from correlated events to combine with mitre_ids
    event_techs = [ev["mitre_technique"] for ev in correlated_events]
    combined_mitre_ids = list(set(mitre_ids + event_techs))

    # 3. Create Scenario and Events in PostgreSQL
    scenario_id = await db_repo.create_scenario(
        name=scenario_name,
        description=scenario_desc,
        mitre_ids=combined_mitre_ids,
        source_dataset=args.source,
        source_path=args.path,
        total_events=len(correlated_events),
        status="passive",  # Default to passive
    )

    # Attach scenario_id to events and insert
    for ev in correlated_events:
        ev["scenario_id"] = scenario_id

    await db_repo.insert_attack_events(correlated_events, status="passive")
    
    print("\n" + "=" * 60)
    print("                    INGESTION SUCCESSFUL")
    print("=" * 60)
    print(f"Scenario Name:      {scenario_name}")
    print(f"Scenario ID:        {scenario_id}")
    print(f"Raw Events Read:    {raw_count}")
    print(f"Correlated Alerts:  {len(correlated_events)}")
    print(f"MITRE Techniques:   {', '.join(mitre_ids)}")
    print("=" * 60)


async def ingest_all_command(args: argparse.Namespace) -> None:
    """Ingests all files in the data directory using compiled metadata mapping."""
    import glob
    from attack_simulator.mapper.mordor_filename import get_mordor_file_info, extract_technique_from_path
    
    target_dir = args.dir
    if not os.path.exists(target_dir):
        print(f"[-] Error: Directory '{target_dir}' does not exist.", file=sys.stderr)
        return

    # Find all zip, tar.gz, and json files
    patterns = [
        os.path.join(target_dir, "*.zip"),
        os.path.join(target_dir, "*.tar.gz"),
        os.path.join(target_dir, "*.json"),
    ]
    files = []
    for pat in patterns:
        files.extend(glob.glob(pat))

    # Deduplicate files
    files = list(set(os.path.abspath(f) for f in files))
    files.sort()

    if not files:
        print(f"[*] No dataset files (*.zip, *.tar.gz, *.json) found in '{target_dir}'.")
        return

    print(f"[*] Found {len(files)} files to ingest. Starting batch ingestion...")
    engine = CorrelationEngine()
    
    skipped = 0
    ingested = 0
    failed = 0

    for file_path in tqdm(files, desc="Ingesting scenarios"):
        filename = os.path.basename(file_path)
        # Skip 0-byte or very small files
        if os.path.getsize(file_path) < 10:
            skipped += 1
            continue

        # Check if scenario is already in DB and has events
        existing_sc = await db_repo.get_scenario_by_path(file_path)
        if existing_sc:
            events = await db_repo.get_scenario_events(existing_sc["id"])
            if events:
                skipped += 1
                continue

        # Resolve metadata
        info = get_mordor_file_info(filename)
        if info:
            scenario_name = info.get("title") or filename
            scenario_desc = info.get("description") or f"Simulated attack using Mordor dataset: {filename}"
            mitre_ids = info.get("techniques", [])
        else:
            scenario_name = os.path.splitext(filename)[0].replace("_", " ").title()
            scenario_desc = f"Simulated attack using dataset: {filename}"
            mitre_ids = [extract_technique_from_path(file_path)]

        # Let's ensure constraints check (character lengths limit: name <= 255, desc <= 1000)
        scenario_name = scenario_name[:255]
        scenario_desc = scenario_desc[:1000]

        # Double check if name already exists in database
        existing_name = await db_repo.get_scenario_by_name(scenario_name)
        if existing_name:
            events = await db_repo.get_scenario_events(existing_name["id"])
            if events:
                skipped += 1
                continue

        # Determine loader
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
                    mitre_ids = metadata.get("mitre_ids", []) or mitre_ids
                raw_events_gen = (e for e in raw_events_list)
            except Exception as e:
                logger.error("ingest_all.failed_to_load_custom", path=file_path, error=str(e))
                failed += 1
                continue

        # Process and correlate events
        try:
            correlated_events = correlate_and_fallback_events(raw_events_gen, mitre_ids, engine)
        except Exception as e:
            logger.error("ingest_all.error_correlating", filename=filename, error=str(e))
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
                logger.error("ingest_all.db_insert_failed_empty", filename=filename, error=str(e))
                failed += 1
            continue


        # Add any runtime matched techniques to mitre_ids
        event_techs = [ev["mitre_technique"] for ev in correlated_events]
        combined_mitre_ids = list(set(mitre_ids + event_techs))

        # Insert to database
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
            logger.error("ingest_all.db_insert_failed", filename=filename, error=str(e))
            failed += 1

    print("\n" + "=" * 60)
    print("                BATCH INGESTION COMPLETE")
    print("=" * 60)
    print(f"Total Files Found:  {len(files)}")
    print(f"Ingested:          {ingested}")
    print(f"Skipped (Exists):  {skipped}")
    print(f"Failed/No Alerts:  {failed}")
    print("=" * 60)


async def run_command(args: argparse.Namespace) -> None:
    """Runs a simulation scenario by sending events to the Agentix webhook."""
    if len(args.scenario) > 255:
        print("[-] Error: Scenario name exceeds 255 characters limit.", file=sys.stderr)
        return
    scenario_name = args.scenario
    sc = await db_repo.get_scenario_by_name(scenario_name)
    if not sc:
        print(f"[-] Error: Ingested scenario '{scenario_name}' not found.", file=sys.stderr)
        return

    events = await db_repo.get_scenario_events(sc["id"])
    if not events:
        print(f"[-] Error: Scenario has no events in database.", file=sys.stderr)
        return

    print(f"[*] Starting attack simulation for: '{scenario_name}'")
    print(f"[*] Total correlated alerts to send: {len(events)}")
    print(f"[*] Target Webhook URL: {WEBHOOK_URL}")

    # Create run
    run_id = await db_repo.create_run(sc["id"], len(events), args.rate)
    
    sent_events = 0
    print("[*] Replaying alerts...")
    for idx, ev in enumerate(tqdm(events)):
        # Send alert
        import copy
        alert_payload = copy.deepcopy(ev["wazuh_alert"])
        alert_payload["simulation_run_id"] = str(run_id)
        session_id = await send_alert_to_webhook(alert_payload)
        
        # Record result placeholder
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
            match_result="PENDING"
        )
        
        sent_events += 1
        await db_repo.update_run_stats(run_id, "RUNNING", sent_events)
        
        if idx < len(events) - 1:
            await asyncio.sleep(args.delay)

    print("\n[*] All alerts sent to webhook. Waiting 8s for Agentix triage pipeline to process playbooks...")
    await asyncio.sleep(8)
    
    # Evaluate run
    print("[*] Evaluating playbook matching results...")
    report = await evaluate_run(run_id)
    
    print("\n" + "=" * 60)
    print("                    SIMULATION RUN COMPLETED")
    print("=" * 60)
    print(f"Run ID:             {run_id}")
    print(f"Total Sent:         {report['total_events']}")
    print(f"Playbooks Matched:  {report['matched']}")
    print(f"Mismatched:         {report['mismatched']}")
    print(f"No Playbook Run:    {report['no_playbook']}")
    print(f"Accuracy Rate:      {report['accuracy_rate']:.2f}%")
    print("=" * 60)
    print(f"To see detailed results, run:")
    print(f"  python -m attack_simulator report --run-id {run_id}")


async def report_command(args: argparse.Namespace) -> None:
    """Displays report for a specific or latest simulation run."""
    if args.run_id and len(args.run_id) > 100:
        print("[-] Error: Run ID exceeds 100 characters limit.", file=sys.stderr)
        return
    run_id = args.run_id
    if not run_id:
        # Fetch latest run
        runs = await db_repo.get_latest_runs(limit=1)
        if not runs:
            print("[-] No simulation runs found in database.")
            return
        run_id = runs[0]["id"]

    # Refresh evaluation
    report = await evaluate_run(run_id)
    results = await db_repo.get_run_results(run_id)

    print("\n" + "=" * 80)
    print(f"                 SIMULATION REPORT FOR RUN: {run_id}")
    print("=" * 80)
    print(f"Status:             {report['status']}")
    print(f"Total Sent Alerts:  {report['total_events']}")
    print(f"Playbooks Matched:  {report['matched']}")
    print(f"Mismatched:         {report['mismatched']}")
    print(f"No Playbook Run:    {report['no_playbook']}")
    print(f"Accuracy Rate:      {report['accuracy_rate']:.2f}%")
    print("-" * 80)
    
    print("\nDETAILED EVENT VERDICTS:")
    print(f"  {'Seq':<4} | {'MITRE Tech':<12} | {'Session ID':<36} | {'Expected PB':<25} | {'Actual PB':<11} | {'Result':<10}")
    print("  " + "-" * 112)
    for res in results:
        actual_str = res["actual_playbook"] or "None"
        expected_str = res["expected_playbook"] or "None"
        session_str = res["session_id"] or "FAILED_SEND"
        print(f"  {res['sequence_order']:<4} | {res['mitre_technique']:<12} | {session_str:<36} | {expected_str:<25} | {actual_str:<11} | {res['match_result']:<10}")
    print("=" * 115)


async def list_command(args: argparse.Namespace) -> None:
    """Lists ingested scenarios."""
    scenarios = await db_repo.list_scenarios()
    if not scenarios:
        print("[*] No scenarios found in database. Ingest one using the ingest command.")
        return

    print("\n" + "=" * 90)
    print("                    INGESTED ATTACK SCENARIOS")
    print("=" * 90)
    print(f"  {'Scenario Name':<30} | {'Source':<8} | {'Status':<8} | {'Events':<6} | {'MITRE Techniques':<25}")
    print("  " + "-" * 86)
    for sc in scenarios:
        techniques = ", ".join(sc["mitre_ids"] or [])
        status_str = sc.get("status", "passive").upper()
        print(f"  {sc['name'][:30]:<30} | {sc['source_dataset']:<8} | {status_str:<8} | {sc['total_events']:<6} | {techniques:<25}")
    print("=" * 90)


async def activate_command(args: argparse.Namespace) -> None:
    """Activates a scenario and deactivates all others."""
    if len(args.scenario) > 255:
        print("[-] Error: Scenario name exceeds 255 characters limit.", file=sys.stderr)
        return
    scenario_name = args.scenario
    sc = await db_repo.get_scenario_by_name(scenario_name)
    if not sc:
        print(f"[-] Error: Scenario '{scenario_name}' not found.", file=sys.stderr)
        return
    await db_repo.activate_scenario(sc["id"])
    print(f"[+] Scenario '{scenario_name}' has been activated. All other scenarios are now set to passive.")


async def gap_report_command(args: argparse.Namespace) -> None:
    """Calculates and reports playbook coverage gap report."""
    print("[*] Analyzing playbooks and simulated techniques for gaps...")
    report = await generate_coverage_report()
    print_ascii_gap_report(report)


def mcp_start_command(args: argparse.Namespace) -> None:
    """Starts the FastMCP Server."""
    os.environ["FASTMCP_TRANSPORT"] = args.transport
    os.environ["FASTMCP_PORT"] = str(args.port)
    
    from attack_simulator.mcp_server import run_server
    run_server()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AttackSimulator: MITRE ATT&CK Attack Simulation Framework for Agentix."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Ingest subcommand
    parser_ingest = subparsers.add_parser("ingest", help="Ingest raw log data and correlate into scenarios.")
    parser_ingest.add_argument("--source", choices=["mordor", "custom"], required=True, help="Data source type")
    parser_ingest.add_argument("--path", required=True, help="Path to raw logs (ZIP for mordor, YAML/JSON for custom)")
    parser_ingest.add_argument("--scenario-name", help="Custom name for the scenario")
    parser_ingest.add_argument("--description", help="Custom description for the scenario")

    # Ingest-all subcommand
    parser_ingest_all = subparsers.add_parser("ingest-all", help="Ingest all files in the data directory using compiled metadata.")
    parser_ingest_all.add_argument("--dir", default="data", help="Directory containing dataset files (default: data)")

    # Download subcommand
    parser_download = subparsers.add_parser("download", help="Download a scenario dataset from a URL.")
    parser_download.add_argument("--url", required=True, help="URL of the Mordor dataset zip file")

    # Run subcommand
    parser_run = subparsers.add_parser("run", help="Run a simulation scenario.")
    parser_run.add_argument("--scenario", required=True, help="Name of the scenario to run")
    parser_run.add_argument("--delay", type=float, default=1.0, help="Delay (in seconds) between sending alerts")
    parser_run.add_argument("--rate", type=float, default=1.0, help="Send rate per second (default: 1.0)")

    # Activate subcommand
    parser_activate = subparsers.add_parser("activate", help="Activate a specific scenario (passive others).")
    parser_activate.add_argument("--scenario", required=True, help="Name of the scenario to activate")

    # Report subcommand
    parser_report = subparsers.add_parser("report", help="Display results for a simulation run.")
    parser_report.add_argument("--run-id", help="Simulation Run UUID (defaults to latest)")

    # List subcommand
    subparsers.add_parser("list", help="List ingested attack scenarios.")

    # Gap Report subcommand
    subparsers.add_parser("gap-report", help="Generate MITRE playbook coverage gap report.")

    # MCP Start subcommand
    parser_mcp = subparsers.add_parser("mcp-start", help="Start the FastMCP Server.")
    parser_mcp.add_argument("--transport", choices=["stdio", "sse"], default="stdio", help="MCP transport type")
    parser_mcp.add_argument("--port", type=int, default=8082, help="SSE Server port")

    args = parser.parse_args()

    # Load configuration
    from attack_simulator.config import WEBHOOK_URL
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        if args.command == "ingest":
            loop.run_until_complete(ingest_command(args))
        elif args.command == "ingest-all":
            loop.run_until_complete(ingest_all_command(args))
        elif args.command == "download":
            loop.run_until_complete(download_command(args))
        elif args.command == "run":
            loop.run_until_complete(run_command(args))
        elif args.command == "activate":
            loop.run_until_complete(activate_command(args))
        elif args.command == "report":
            loop.run_until_complete(report_command(args))
        elif args.command == "list":
            loop.run_until_complete(list_command(args))
        elif args.command == "gap-report":
            loop.run_until_complete(gap_report_command(args))
        elif args.command == "mcp-start":
            mcp_start_command(args)
    except KeyboardInterrupt:
        print("\n[-] Cancelled by user.")
    finally:
        # Clean up database connections
        try:
            loop.run_until_complete(db_repo.close())
        except Exception:
            pass
        loop.close()


if __name__ == "__main__":
    main()
