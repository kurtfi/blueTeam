#!/usr/bin/env python3
"""
Ingestion CLI tool for AttackSimulator.
Parses local files and submits them to the simulator's REST API.
"""

import argparse
import asyncio
import os
import sys

import httpx

from dataset_ingestor.ingestion import IngestionService
from dataset_ingestor.loader.dag_loader import DagScenarioLoader


async def post_payload(client: httpx.AsyncClient, api_url: str, endpoint: str, payload: dict) -> dict:
    url = f"{api_url.rstrip('/')}/{endpoint.lstrip('/')}"
    try:
        response = await client.post(url, json=payload, timeout=60.0)
        if response.status_code != 200:
            return {"status": "error", "message": f"HTTP {response.status_code}: {response.text}"}
        return response.json()
    except Exception as e:
        return {"status": "error", "message": f"Connection failed: {e}"}


async def download_command(args: argparse.Namespace) -> None:
    """Downloads a dataset from a URL to data/ directory."""
    service = IngestionService()
    try:
        local_path = await service.download_dataset(args.url)
        print(f"[+] Download complete: {local_path}")
    except Exception as e:
        print(f"[-] Download failed: {e}", file=sys.stderr)
        sys.exit(1)


def confirm_prompt(prompt: str, default: bool = False) -> bool:
    """Prompts the user for a yes/no confirmation on stdin."""
    try:
        sys.stdout.write(prompt)
        sys.stdout.flush()
        choice = sys.stdin.readline().strip().lower()
        if not choice:
            return default
        return choice in ("y", "yes")
    except Exception:
        return False


async def ingest_command(args: argparse.Namespace) -> None:
    """Ingests raw attack telemetry, correlates events, and posts scenario metadata to REST API."""
    service = IngestionService()
    print(f"[*] Parsing and correlating {args.source} source: {args.path} ...")

    mitre_ids_list = None
    if getattr(args, "mitre_ids", None):
        mitre_ids_list = [t.strip() for t in args.mitre_ids.split(",") if t.strip()]

    try:
        payload = service.prepare_scenario_payload(
            path=args.path,
            source_type=args.source,
            scenario_name=args.scenario_name,
            description=args.description,
            mitre_ids=mitre_ids_list,
        )
    except Exception as e:
        print(f"[-] Parsing failed: {e}", file=sys.stderr)
        sys.exit(1)

    print("\n" + "=" * 60)
    print("                    INGESTION SUMMARY")
    print("=" * 60)
    print(f"Scenario Name:      {payload['name']}")
    print(f"Description:        {payload.get('description', '')}")
    print(f"Source Type:        {args.source}")
    print(f"Source Path:        {args.path}")
    print(f"MITRE Techniques:   {', '.join(payload.get('mitre_ids', []))}")
    print(f"Total Events:       {len(payload.get('events', []))}")
    print("=" * 60)

    # Prompt if not --yes
    if not getattr(args, "yes", False):
        if not confirm_prompt("Do you want to proceed with the ingestion? [y/N]: "):
            print("[-] Ingestion aborted.")
            return

    print(f"[*] Posting scenario '{payload['name']}' to API at {args.api_url}...")
    async with httpx.AsyncClient() as client:
        res = await post_payload(client, args.api_url, "/simulations/scenarios/linear", payload)
        if res.get("status") == "success":
            print("\n" + "=" * 60)
            print("                    INGESTION SUCCESSFUL (VIA API)")
            print("=" * 60)
            print(f"Scenario Name:      {payload['name']}")
            print(f"Scenario ID:        {res.get('scenario_id')}")
            print(f"Correlated Alerts:  {res.get('total_events')}")
            print(f"MITRE Techniques:   {', '.join(payload.get('mitre_ids', []))}")
            print("=" * 60)
        else:
            print(f"[-] API Ingestion failed: {res.get('message')}", file=sys.stderr)
            sys.exit(1)


async def ingest_all_command(args: argparse.Namespace) -> None:
    """Ingests all files in the data directory and posts them to API."""
    service = IngestionService()
    print(f"[*] Analyzing target directory '{args.dir}' for scenarios...")

    try:
        payloads = service.prepare_all_scenarios(args.dir)
    except Exception as e:
        print(f"[-] Directory analysis failed: {e}", file=sys.stderr)
        sys.exit(1)

    if not payloads:
        print(f"[-] No valid scenarios found in directory: {args.dir}")
        return

    print("\n" + "=" * 60)
    print("                BATCH INGESTION SUMMARY")
    print("=" * 60)
    print(f"Total Scenarios Found: {len(payloads)}")
    print("Scenarios list:")
    for idx, p in enumerate(payloads, 1):
        print(f"  {idx}. {p['name']} ({len(p.get('events', []))} events, Techs: {', '.join(p.get('mitre_ids', []))})")
    print("=" * 60)

    # Prompt if not --yes
    if not getattr(args, "yes", False):
        if not confirm_prompt("Do you want to proceed with the batch ingestion? [y/N]: "):
            print("[-] Ingestion aborted.")
            return

    print(f"[*] Submitting {len(payloads)} scenarios to API...")
    results = {"total": len(payloads), "ingested": 0, "failed": 0}

    async with httpx.AsyncClient() as client:
        for payload in payloads:
            res = await post_payload(client, args.api_url, "/simulations/scenarios/linear", payload)
            if res.get("status") == "success":
                results["ingested"] += 1
                print(f"[+] Ingested: {payload['name']}")
            else:
                results["failed"] += 1
                print(f"[-] Failed {payload['name']}: {res.get('message')}", file=sys.stderr)

    print("\n" + "=" * 60)
    print("                BATCH INGESTION COMPLETE")
    print("=" * 60)
    print(f"Total Scenarios Found: {results['total']}")
    print(f"Ingested:              {results['ingested']}")
    print(f"Failed:                {results['failed']}")
    print("=" * 60)


async def ingest_dags_command(args: argparse.Namespace) -> None:
    """Ingests all DAG scenarios in YAML format and posts to API."""
    loader = DagScenarioLoader()
    print(f"[*] Analyzing target directory '{args.dir}' for DAG scenarios...")

    try:
        payloads = loader.load_all_dags(args.dir, data_dir=args.data_dir)
    except Exception as e:
        print(f"[-] DAG directory analysis failed: {e}", file=sys.stderr)
        sys.exit(1)

    if not payloads:
        print(f"[-] No valid DAG scenarios found in directory: {args.dir}")
        return

    print("\n" + "=" * 60)
    print("                 DAG INGESTION SUMMARY")
    print("=" * 60)
    print(f"Total DAGs Found: {len(payloads)}")
    print("DAG list:")
    for idx, p in enumerate(payloads, 1):
        print(f"  {idx}. {p['name']} (Techs: {', '.join(p.get('mitre_ids', []))})")
    print("=" * 60)

    # Prompt if not --yes
    if not getattr(args, "yes", False):
        if not confirm_prompt("Do you want to proceed with the DAG ingestion? [y/N]: "):
            print("[-] Ingestion aborted.")
            return

    print(f"[*] Submitting {len(payloads)} DAG scenarios to API...")
    results = {"total": len(payloads), "ingested": 0, "failed": 0}

    async with httpx.AsyncClient() as client:
        for payload in payloads:
            res = await post_payload(client, args.api_url, "/simulations/scenarios/dag", payload)
            if res.get("status") == "success":
                results["ingested"] += 1
                print(f"[+] Ingested DAG: {payload['name']}")
            else:
                results["failed"] += 1
                print(f"[-] Failed DAG {payload['name']}: {res.get('message')}", file=sys.stderr)

    print("\n" + "=" * 60)
    print("                DAG INGESTION COMPLETE")
    print("=" * 60)
    print(f"Total DAGs Found:   {results['total']}")
    print(f"Ingested:           {results['ingested']}")
    print(f"Failed:             {results['failed']}")
    print("=" * 60)


def main() -> None:
    parser = argparse.ArgumentParser(description="DatasetIngestor Ingestion Tool: Ingest scenarios via API.")
    parser.add_argument(
        "--api-url",
        default=os.getenv("ATTACK_SIMULATOR_API_URL", "http://localhost:8083/v1"),
        help="REST API URL of the running AttackSimulator server (default: http://localhost:8083/v1)",
    )
    parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="Skip confirmation prompt before ingestion",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Ingest subcommand
    parser_ingest = subparsers.add_parser("ingest", help="Ingest raw log data and correlate into scenarios.")
    parser_ingest.add_argument("--source", choices=["mordor", "custom"], required=True, help="Data source type")
    parser_ingest.add_argument("--path", required=True, help="Path to raw logs (ZIP for mordor, YAML/JSON for custom)")
    parser_ingest.add_argument("--scenario-name", help="Custom name for the scenario")
    parser_ingest.add_argument("--description", help="Custom description for the scenario")
    parser_ingest.add_argument(
        "--mitre-ids",
        help="Comma-separated MITRE Technique IDs to override or seed (e.g., T1003.001,T1021)",
    )

    # Ingest-all subcommand
    parser_ingest_all = subparsers.add_parser(
        "ingest-all", help="Ingest all files in the data directory using compiled metadata."
    )
    parser_ingest_all.add_argument("--dir", default="data", help="Directory containing dataset files (default: data)")

    # Ingest-dags subcommand
    parser_ingest_dags = subparsers.add_parser("ingest-dags", help="Ingest all DAG scenarios in YAML format.")
    parser_ingest_dags.add_argument(
        "--dir",
        default=os.path.abspath(
            os.path.join(
                os.path.dirname(__file__), "..", "..", "AttackSimulator", "attack_simulator", "scenarios", "dags"
            )
        ),
        help="Directory containing YAML DAG files",
    )
    parser_ingest_dags.add_argument("--data-dir", default="data", help="Directory containing dataset files")

    # Download subcommand
    parser_download = subparsers.add_parser("download", help="Download a scenario dataset from a URL.")
    parser_download.add_argument("--url", required=True, help="URL of the Mordor dataset zip file")

    args = parser.parse_args()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        if args.command == "ingest":
            loop.run_until_complete(ingest_command(args))
        elif args.command == "ingest-all":
            loop.run_until_complete(ingest_all_command(args))
        elif args.command == "ingest-dags":
            loop.run_until_complete(ingest_dags_command(args))
        elif args.command == "download":
            loop.run_until_complete(download_command(args))
    except KeyboardInterrupt:
        print("\n[-] Cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Command failed: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        loop.close()


if __name__ == "__main__":
    main()
