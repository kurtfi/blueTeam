"""
Ingestion service for raw security event telemetry.
Parses, correlates, and generates standard API payloads without direct database access.
"""

import glob
import hashlib
import os
from collections.abc import Generator
from typing import Any

import httpx
import structlog
from attack_simulator.mapper.mitre_catalog import get_mitre_info
from attack_simulator.mapper.wazuh_template import generate_wazuh_alert, strip_information_leakage
from dataset_ingestor.mapper.mordor_filename import extract_technique_from_path, get_mordor_file_info

from dataset_ingestor.correlation.engine import CorrelationEngine
from dataset_ingestor.loader.custom import CustomLoader
from dataset_ingestor.loader.mordor import MordorLoader

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
    and outputting REST API payloads.
    """

    async def download_dataset(self, url: str) -> str:
        """
        Downloads a dataset from a URL to the local data/ directory.
        Returns the absolute local path to the downloaded file.
        """
        from urllib.parse import urlparse

        parsed_url = urlparse(url)
        filename = os.path.basename(parsed_url.path)
        if not filename or filename in (".", ".."):
            raise ValueError(f"Could not extract a valid filename from URL: {url}")

        dest_dir = "data"
        abs_dest_dir = os.path.abspath(dest_dir)
        local_path = os.path.abspath(os.path.join(abs_dest_dir, filename))

        # Strict containment check to prevent path traversal
        if not local_path.startswith(abs_dest_dir + os.sep) and local_path != abs_dest_dir:
            raise ValueError(f"Path traversal detected in URL: {url}")

        if os.path.exists(local_path) and os.path.getsize(local_path) > 100:
            logger.info("ingestion.file_already_downloaded", filename=filename)
            return local_path

        try:
            os.makedirs(dest_dir, exist_ok=True)
            logger.info("ingestion.download_started", url=url, dest=local_path)
            async with httpx.AsyncClient(follow_redirects=True, timeout=60.0) as client:
                response = await client.get(url)
                if response.status_code != 200:
                    raise Exception(f"HTTP Status {response.status_code}")
                with open(local_path, "wb") as f:
                    f.write(response.content)
            logger.info("ingestion.download_completed", path=local_path, size_bytes=len(response.content))
            return local_path
        except Exception as e:
            raise Exception(f"Failed to download file from {url}: {e}")

    def prepare_scenario_payload(
        self, path: str, source_type: str, scenario_name: str | None = None, description: str | None = None
    ) -> dict[str, Any]:
        """
        Parses and correlates the scenario file/dataset and returns a dict matching the REST API schema.
        """
        filename = os.path.basename(path)
        local_path = os.path.abspath(path)

        if not os.path.exists(local_path):
            # Try to resolve relative to workspace root
            cur = os.path.dirname(os.path.abspath(__file__))
            found = False
            for _ in range(5):
                candidate = os.path.join(cur, "data", filename)
                if os.path.exists(candidate):
                    local_path = os.path.abspath(candidate)
                    found = True
                    break
                cur = os.path.dirname(cur)
            if not found:
                raise FileNotFoundError(f"Source path does not exist: {local_path}")

        if source_type == "mordor":
            loader = MordorLoader()
            resolved_name = (
                scenario_name or os.path.splitext(os.path.basename(local_path))[0].replace("_", " ").title()
            )
            resolved_desc = description or f"Simulated attack using Mordor dataset: {os.path.basename(local_path)}"

            info = get_mordor_file_info(os.path.basename(local_path))
            if info:
                mitre_ids = info.get("techniques", [])
            else:
                mitre_ids = [extract_technique_from_path(local_path)]

            raw_events_gen = loader.load(local_path)
        else:  # custom
            loader_custom = CustomLoader()
            metadata, raw_events_list = loader_custom.load_scenario_file(local_path)
            resolved_name = scenario_name or metadata["name"]
            resolved_desc = description or metadata["description"]
            mitre_ids = metadata.get("mitre_ids", [])
            raw_events_gen = (e for e in raw_events_list)

        # Correlate events
        engine = CorrelationEngine()
        correlated_events = correlate_and_fallback_events(raw_events_gen, mitre_ids, engine)

        if not correlated_events:
            raise Exception("Ingestion payload empty: 0 alerts generated from this raw data.")

        # Clean/sanitize information leakage from alerts
        for ev in correlated_events:
            ev["wazuh_alert"] = strip_information_leakage(ev["wazuh_alert"], ev["mitre_technique"])

        event_techs = [ev["mitre_technique"] for ev in correlated_events]
        combined_mitre_ids = list(set(mitre_ids + event_techs))

        return {
            "name": resolved_name,
            "description": resolved_desc,
            "mitre_ids": combined_mitre_ids,
            "source_dataset": source_type,
            "source_path": path,
            "events": correlated_events,
        }

    def prepare_all_scenarios(self, directory_path: str = "data") -> list[dict[str, Any]]:
        """
        Finds and prepares payloads for all valid scenario files in the directory.
        """
        if not os.path.exists(directory_path):
            # Fallback to searching parent directories for the workspace root's data folder
            cur = os.path.dirname(os.path.abspath(__file__))
            found = False
            for _ in range(5):
                candidate = os.path.join(cur, "data")
                if os.path.exists(candidate):
                    directory_path = candidate
                    found = True
                    break
                cur = os.path.dirname(cur)
            if not found:
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

        payloads = []
        for file_path in files:
            filename = os.path.basename(file_path)
            if os.path.getsize(file_path) < 10:
                continue

            try:
                payload = self.prepare_scenario_payload(file_path, "mordor" if filename.endswith((".zip", ".tar.gz")) else "custom")
                payloads.append(payload)
            except Exception as e:
                logger.error("ingestion.failed_payload_prep", path=file_path, error=str(e))

        return payloads
