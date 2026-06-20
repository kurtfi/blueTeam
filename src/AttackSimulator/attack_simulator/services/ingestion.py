"""
Service layer for scenario ingestion and dataset management.
"""

import glob
import hashlib
import os
from collections.abc import Generator
from typing import Any

import httpx
import structlog
from tqdm import tqdm  # type: ignore[import-untyped]

from attack_simulator.correlation.engine import CorrelationEngine
from attack_simulator.exceptions import DatasetDownloadError, DuplicateScenarioError, IngestionError
from attack_simulator.loader.custom import CustomLoader
from attack_simulator.loader.mordor import MordorLoader
from attack_simulator.mapper.wazuh_template import strip_information_leakage
from attack_simulator.models import db_repo

logger = structlog.get_logger(__name__)


def compute_sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def correlate_and_fallback_events(
    raw_events_gen: Generator[dict[str, Any], None, None], mitre_ids: list[str], engine: CorrelationEngine
) -> list[dict[str, Any]]:
    """
    Correlates raw events with rules and filters alerts not matching the scenario's techniques.
    Generates fallback alerts for execution events if no rules match.
    """
    from attack_simulator.mapper.mitre_catalog import get_mitre_info
    from attack_simulator.mapper.wazuh_template import generate_wazuh_alert

    correlated_events = []
    seq_order = 1
    primary_technique = mitre_ids[0] if mitre_ids else "T1059"

    # Normalize mitre_ids to facilitate easy checking
    normalized_mitre_ids = {m.upper().strip() for m in mitre_ids}
    parent_ids = set()
    for m in normalized_mitre_ids:
        if "." in m:
            parent_ids.add(m.split(".")[0])
    normalized_mitre_ids.update(parent_ids)

    first_few_events: list[dict[str, Any]] = []

    for raw in raw_events_gen:
        if len(first_few_events) < 3:
            first_few_events.append(raw)

        alerts = engine.process_event(raw)
        matched_any = False

        for alert in alerts:
            alert_tech = alert["rule"]["mitre"]["id"][0].upper().strip()
            if alert_tech in normalized_mitre_ids:
                raw_log_str = alert.get("full_log", "")
                raw_hash = compute_sha256(raw_log_str)
                correlated_events.append(
                    {
                        "sequence_order": seq_order,
                        "mitre_technique": alert["rule"]["mitre"]["id"][0],
                        "mitre_tactic": alert["rule"]["mitre"]["tactic"][0],
                        "correlation_type": "direct"
                        if "aggregation" not in alert["full_log"].lower()
                        else "aggregation",
                        "raw_event_count": 1,
                        "correlation_rule": alert["rule"]["description"],
                        "wazuh_alert": alert,
                        "raw_log_hash": raw_hash,
                    }
                )
                seq_order += 1
                matched_any = True

        if not matched_any:
            event_id = str(raw.get("EventID") or raw.get("event_id") or raw.get("eventID") or "")
            command_line = raw.get("CommandLine") or raw.get("message") or ""

            is_execution = event_id in ("1", "3", "11", "12", "13", "4104", "4662", "4688", "7045", "5156") or bool(
                command_line
            )

            if is_execution:
                alert = generate_wazuh_alert(primary_technique, raw)
                raw_log_str = alert.get("full_log", "")
                raw_hash = compute_sha256(raw_log_str)

                mitre_info = get_mitre_info(primary_technique)

                correlated_events.append(
                    {
                        "sequence_order": seq_order,
                        "mitre_technique": primary_technique,
                        "mitre_tactic": mitre_info.get("tactic", "Unknown Tactic"),
                        "correlation_type": "direct",
                        "raw_event_count": 1,
                        "correlation_rule": f"Fallback alert for {primary_technique} execution",
                        "wazuh_alert": alert,
                        "raw_log_hash": raw_hash,
                    }
                )
                seq_order += 1

    if not correlated_events and first_few_events:
        logger.info("correlate_and_fallback.failsafe_triggered", mitre_ids=mitre_ids)
        for raw in first_few_events:
            alert = generate_wazuh_alert(primary_technique, raw)
            raw_log_str = alert.get("full_log", "")
            raw_hash = compute_sha256(raw_log_str)

            mitre_info = get_mitre_info(primary_technique)

            correlated_events.append(
                {
                    "sequence_order": seq_order,
                    "mitre_technique": primary_technique,
                    "mitre_tactic": mitre_info.get("tactic", "Unknown Tactic"),
                    "correlation_type": "direct",
                    "raw_event_count": 1,
                    "correlation_rule": f"Fallback alert for {primary_technique} execution (failsafe)",
                    "wazuh_alert": alert,
                    "raw_log_hash": raw_hash,
                }
            )
            seq_order += 1

    return correlated_events


class IngestionService:
    """
    Handles downloading scenario datasets, loading and correlating telemetry,
    and committing scenario records to the database repository.
    """

    async def download_dataset(self, url: str) -> str:
        """
        Downloads a dataset from a URL to the local data/ directory.
        Returns the absolute local path to the downloaded file.
        """
        if len(url) > 1000:
            raise ValueError("URL exceeds 1000 characters limit.")

        filename = os.path.basename(url)
        dest_dir = "data"
        local_path = os.path.abspath(os.path.join(dest_dir, filename))

        # Check if already downloaded
        if os.path.exists(local_path) and os.path.getsize(local_path) > 100:
            raise DuplicateScenarioError(f"File '{filename}' is already downloaded. Download blocked.")

        # Check if already in database
        existing_sc = await db_repo.get_scenario_by_path(url)
        if not existing_sc:
            existing_sc = await db_repo.get_scenario_by_path(local_path)
        if existing_sc:
            events = await db_repo.get_scenario_events(existing_sc["id"])
            if events:
                raise DuplicateScenarioError(
                    f"Scenario associated with '{filename}' is already ingested and has events. Download blocked."
                )

        try:
            os.makedirs(dest_dir, exist_ok=True)
            logger.info("ingestion.download_started", url=url, dest=local_path)
            async with httpx.AsyncClient(follow_redirects=True, timeout=60.0) as client:
                response = await client.get(url)
                if response.status_code != 200:
                    raise DatasetDownloadError(f"HTTP Status {response.status_code}")
                with open(local_path, "wb") as f:
                    f.write(response.content)
            logger.info("ingestion.download_completed", path=local_path, size_bytes=len(response.content))
            return local_path
        except Exception as e:
            if isinstance(e, (DuplicateScenarioError, DatasetDownloadError)):
                raise
            raise DatasetDownloadError(f"Failed to download file from {url}: {e}")

    async def ingest_scenario(
        self, path: str, source_type: str, scenario_name: str | None = None, description: str | None = None
    ) -> str:
        """
        Ingests a single scenario file or URL, correlates alerts, and saves it.
        Returns the created scenario_id.
        """
        if scenario_name and len(scenario_name) > 255:
            raise ValueError("Scenario name exceeds 255 characters limit.")
        if description and len(description) > 1000:
            raise ValueError("Description exceeds 1000 characters limit.")
        if len(path) > 1000:
            raise ValueError("Path/URL exceeds 1000 characters limit.")

        is_url = path.startswith("http://") or path.startswith("https://")
        filename = os.path.basename(path)
        dest_dir = "data"
        local_path = os.path.abspath(os.path.join(dest_dir, filename)) if is_url else os.path.abspath(path)

        # Check: Download duplication
        if is_url and os.path.exists(local_path) and os.path.getsize(local_path) > 100:
            raise DuplicateScenarioError(f"File '{filename}' is already downloaded. Ingestion blocked.")

        # Check: Scenario database duplication
        existing_sc = await db_repo.get_scenario_by_path(path)
        if not existing_sc and is_url:
            existing_sc = await db_repo.get_scenario_by_path(local_path)
        if not existing_sc:
            fallback_name = scenario_name or os.path.splitext(os.path.basename(local_path))[0].replace("_", " ").title()
            existing_sc = await db_repo.get_scenario_by_name(fallback_name)

        if existing_sc:
            events = await db_repo.get_scenario_events(existing_sc["id"])
            if events:
                raise DuplicateScenarioError(
                    f"Scenario '{existing_sc['name']}' is already ingested and has events in the database. Ingestion blocked."
                )

        # If it is a URL, download it
        if is_url:
            await self.download_dataset(path)
            source_path = local_path
        else:
            source_path = local_path

        if not os.path.exists(source_path):
            raise FileNotFoundError(f"Source path does not exist: {source_path}")

        # Initialize appropriate loader and metadata mappings
        from attack_simulator.mapper.mordor_filename import extract_technique_from_path, get_mordor_file_info

        if source_type == "mordor":
            loader = MordorLoader()
            resolved_name = (
                scenario_name or os.path.splitext(os.path.basename(source_path))[0].replace("_", " ").title()
            )
            resolved_desc = description or f"Simulated attack using Mordor dataset: {os.path.basename(source_path)}"

            existing_name = await db_repo.get_scenario_by_name(resolved_name)
            if existing_name:
                raise DuplicateScenarioError(f"Scenario with name '{resolved_name}' is already ingested.")

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
                resolved_name = scenario_name or metadata["name"]
                resolved_desc = description or metadata["description"]
                mitre_ids = metadata.get("mitre_ids", [])

                existing_name = await db_repo.get_scenario_by_name(resolved_name)
                if existing_name:
                    raise DuplicateScenarioError(f"Scenario with name '{resolved_name}' is already ingested.")

                raw_events_gen = (e for e in raw_events_list)
            except Exception as e:
                if isinstance(e, DuplicateScenarioError):
                    raise
                raise IngestionError(f"Failed to load custom scenario file: {e}")

        # Correlate events
        engine = CorrelationEngine()
        try:
            correlated_events = correlate_and_fallback_events(raw_events_gen, mitre_ids, engine)
        except Exception as e:
            raise IngestionError(f"Correlation processing failed: {e}")

        if not correlated_events:
            raise IngestionError("Ingestion cancelled: 0 alerts generated from this raw data.")

        # Clean/sanitize information leakage from alerts before inserting into DB
        for ev in correlated_events:
            ev["wazuh_alert"] = strip_information_leakage(ev["wazuh_alert"], ev["mitre_technique"])

        # Extract MITRE IDs from correlated events
        event_techs = [ev["mitre_technique"] for ev in correlated_events]
        combined_mitre_ids = list(set(mitre_ids + event_techs))

        # Create scenario in DB
        scenario_id = await db_repo.create_scenario(
            name=resolved_name,
            description=resolved_desc,
            mitre_ids=combined_mitre_ids,
            source_dataset=source_type,
            source_path=path,
            total_events=len(correlated_events),
            status="passive",
        )

        # Attach scenario ID and insert events
        for ev in correlated_events:
            ev["scenario_id"] = scenario_id

        await db_repo.insert_attack_events(correlated_events, status="passive")
        logger.info(
            "ingestion.completed",
            scenario_name=resolved_name,
            scenario_id=scenario_id,
            events_count=len(correlated_events),
        )
        return scenario_id

    async def ingest_all_scenarios(self, directory_path: str = "data") -> dict[str, int]:
        """
        Ingests all valid files in a directory using compiled metadata mappings.
        """
        from attack_simulator.mapper.mordor_filename import extract_technique_from_path, get_mordor_file_info

        if not os.path.exists(directory_path):
            raise FileNotFoundError(f"Directory '{directory_path}' does not exist.")

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

        results = {"total": len(files), "ingested": 0, "skipped": 0, "failed": 0}
        if not files:
            return results

        engine = CorrelationEngine()

        for file_path in tqdm(files, desc="Ingesting scenarios"):
            filename = os.path.basename(file_path)
            if os.path.getsize(file_path) < 10:
                results["skipped"] += 1
                continue

            existing_sc = await db_repo.get_scenario_by_path(file_path)
            if existing_sc:
                events = await db_repo.get_scenario_events(existing_sc["id"])
                if events:
                    results["skipped"] += 1
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
                    results["skipped"] += 1
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
                        mitre_ids = metadata.get("mitre_ids", []) or mitre_ids
                    raw_events_gen = (e for e in raw_events_list)
                except Exception as e:
                    logger.error("ingest_all.failed_to_load_custom", path=file_path, error=str(e))
                    results["failed"] += 1
                    continue

            try:
                correlated_events = correlate_and_fallback_events(raw_events_gen, mitre_ids, engine)
            except Exception as e:
                logger.error("ingest_all.error_correlating", filename=filename, error=str(e))
                results["failed"] += 1
                continue

            if not correlated_events:
                try:
                    await db_repo.create_scenario(
                        name=scenario_name,
                        description=scenario_desc,
                        mitre_ids=mitre_ids,
                        source_dataset="mordor" if is_mordor else "custom",
                        source_path=file_path,
                        total_events=0,
                        status="passive",
                    )
                    results["ingested"] += 1
                except Exception as e:
                    logger.error("ingest_all.db_insert_failed_empty", filename=filename, error=str(e))
                    results["failed"] += 1
                continue

            # Clean/sanitize information leakage before inserting into DB
            for ev in correlated_events:
                ev["wazuh_alert"] = strip_information_leakage(ev["wazuh_alert"], ev["mitre_technique"])

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
                results["ingested"] += 1
            except Exception as e:
                logger.error("ingest_all.db_insert_failed", filename=filename, error=str(e))
                results["failed"] += 1

        return results
