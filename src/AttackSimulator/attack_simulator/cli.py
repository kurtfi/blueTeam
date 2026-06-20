"""
CLI entry point for AttackSimulator.
"""

import argparse
import asyncio
import os
import sys

import structlog
from tqdm import tqdm  # type: ignore[import-untyped]

from attack_simulator.config import WEBHOOK_URL
from attack_simulator.evaluator.gap_analyzer import generate_coverage_report, print_ascii_gap_report
from attack_simulator.evaluator.playbook_match import evaluate_run
from attack_simulator.models import db_repo
from attack_simulator.services.ingestion import IngestionService
from attack_simulator.services.simulation import SimulationService

logger = structlog.get_logger(__name__)


async def download_command(args: argparse.Namespace) -> None:
    """Downloads a dataset from a URL to data/ directory with duplication checks."""
    service = IngestionService()
    local_path = await service.download_dataset(args.url)
    print(f"[+] Download complete: {local_path}")


async def ingest_command(args: argparse.Namespace) -> None:
    """Ingests raw attack telemetry, correlates events, and stores scenario metadata."""
    service = IngestionService()

    print(f"[*] Starting ingestion from {args.source} source: {args.path} ...")
    scenario_id = await service.ingest_scenario(
        path=args.path, source_type=args.source, scenario_name=args.scenario_name, description=args.description
    )

    fallback_name = args.scenario_name or os.path.splitext(os.path.basename(args.path))[0].replace("_", " ").title()
    sc = await db_repo.get_scenario_by_name(fallback_name)

    sc_name = sc["name"] if sc else (args.scenario_name or "Unknown")
    sc_total = sc["total_events"] if sc else 0
    sc_mitre = ", ".join(sc["mitre_ids"]) if sc and sc["mitre_ids"] else ""

    print("\n" + "=" * 60)
    print("                    INGESTION SUCCESSFUL")
    print("=" * 60)
    print(f"Scenario Name:      {sc_name}")
    print(f"Scenario ID:        {scenario_id}")
    print(f"Correlated Alerts:  {sc_total}")
    print(f"MITRE Techniques:   {sc_mitre}")
    print("=" * 60)


async def ingest_all_command(args: argparse.Namespace) -> None:
    """Ingests all files in the data directory using compiled metadata mapping."""
    service = IngestionService()

    print(f"[*] Analyzing target directory '{args.dir}' for scenarios...")
    results = await service.ingest_all_scenarios(args.dir)

    print("\n" + "=" * 60)
    print("                BATCH INGESTION COMPLETE")
    print("=" * 60)
    print(f"Total Files Found:  {results['total']}")
    print(f"Ingested:          {results['ingested']}")
    print(f"Skipped (Exists):  {results['skipped']}")
    print(f"Failed/No Alerts:  {results['failed']}")
    print("=" * 60)


async def run_command(args: argparse.Namespace) -> None:
    """Runs a simulation scenario by sending events to the Agentix webhook."""
    service = SimulationService()

    scenario_name = args.scenario
    sc = await db_repo.get_scenario_by_name(scenario_name)
    if not sc:
        raise FileNotFoundError(f"Ingested scenario '{scenario_name}' not found.")

    events = await db_repo.get_scenario_events(sc["id"])
    if not events:
        raise ValueError("Scenario has no events in database.")

    print(f"[*] Starting attack simulation for: '{scenario_name}'")
    print(f"[*] Total correlated alerts to send: {len(events)}")
    print(f"[*] Target Webhook URL: {WEBHOOK_URL}")

    # Create run
    run_id = await db_repo.create_run(sc["id"], len(events), args.rate)

    sent_events = 0
    print("[*] Replaying alerts...")
    for idx, ev in enumerate(tqdm(events)):
        # Send alert using the service's alert sender
        import copy

        alert_payload = copy.deepcopy(ev["wazuh_alert"])
        alert_payload["simulation_run_id"] = str(run_id)

        session_id = await service.alert_sender.send(alert_payload, ev["mitre_technique"])

        # Record result placeholder using the service's playbook registry gateway
        expected_mitre = [ev["mitre_technique"]]
        expected_list = []
        try:
            candidates = service.playbook_gateway.find_playbooks_for_mitre(expected_mitre)
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
    print("To see detailed results, run:")
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
    print(
        f"  {'Seq':<4} | {'MITRE Tech':<12} | {'Session ID':<36} | {'Expected PB':<25} | {'Actual PB':<11} | {'Result':<10}"
    )
    print("  " + "-" * 112)
    for res in results:
        actual_str = res["actual_playbook"] or "None"
        expected_str = res["expected_playbook"] or "None"
        session_str = res["session_id"] or "FAILED_SEND"
        print(
            f"  {res['sequence_order']:<4} | {res['mitre_technique']:<12} | {session_str:<36} | {expected_str:<25} | {actual_str:<11} | {res['match_result']:<10}"
        )
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
        print(
            f"  {sc['name'][:30]:<30} | {sc['source_dataset']:<8} | {status_str:<8} | {sc['total_events']:<6} | {techniques:<25}"
        )
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
    parser_ingest_all = subparsers.add_parser(
        "ingest-all", help="Ingest all files in the data directory using compiled metadata."
    )
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
        sys.exit(1)
    except Exception as e:
        print(f"[-] Command failed: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        # Clean up database connections
        try:
            loop.run_until_complete(db_repo.close())
        except Exception:
            pass
        loop.close()


if __name__ == "__main__":
    main()
