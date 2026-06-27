"""
DAG Scenario Loader for external Ingestion script.
Reads YAML DAG definitions, resolves step log zips, correlates alerts, and returns the payload structure.
"""

import os
from typing import Any

import structlog
import yaml
from dataset_ingestor.correlation.engine import CorrelationEngine
from dataset_ingestor.ingestion import correlate_and_fallback_events
from dataset_ingestor.loader.factory import DatasetLoaderFactory

from agentic_common.mapper.wazuh_template import strip_information_leakage

logger = structlog.get_logger(__name__)


def resolve_log_path(log_source: str, data_dir: str = "data", scenario_dir: str | None = None) -> str:
    """
    Resolves log source path relative to scenario_dir, data_dir, or parent directories.
    """
    # 1. Try resolving relative to scenario file's directory first
    if scenario_dir:
        candidate = os.path.abspath(os.path.join(scenario_dir, os.path.basename(log_source)))
        if os.path.exists(candidate):
            return candidate
        # Also try direct/relative path from scenario_dir
        candidate2 = os.path.abspath(os.path.join(scenario_dir, log_source))
        if os.path.exists(candidate2):
            return candidate2

    # 2. Try resolving relative to data_dir
    resolved_path = os.path.abspath(os.path.join(data_dir, os.path.basename(log_source)))
    if not os.path.exists(resolved_path):
        # Fallback to direct path or relative path
        resolved_path = os.path.abspath(log_source)

    if not os.path.exists(resolved_path):
        # Check parent directories for workspace root "data" folder
        cur = os.path.dirname(os.path.abspath(__file__))
        for _ in range(5):
            candidate = os.path.join(cur, "data", os.path.basename(log_source))
            if os.path.exists(candidate):
                resolved_path = os.path.abspath(candidate)
                break
            cur = os.path.dirname(cur)
    return resolved_path


class DagScenarioLoader:
    """
    Loads and processes multi-stage DAG scenarios from YAML files.
    """

    def __init__(
        self,
        correlation_engine: CorrelationEngine | None = None,
        loader_factory: Any = None,
    ) -> None:
        self.correlation_engine = correlation_engine or CorrelationEngine()
        self.loader_factory = loader_factory or DatasetLoaderFactory

    def load_dag_scenario(self, file_path: str, data_dir: str = "data") -> dict[str, Any]:
        """
        Loads a single YAML DAG scenario, resolves raw logs for each step,
        correlates alerts, and returns the parsed payload structure.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"DAG definition file not found: {file_path}")

        logger.info("dag_loader.loading_yaml", path=file_path)
        with open(file_path, encoding="utf-8") as f:
            dag_data = yaml.safe_load(f)

        name = dag_data.get("name")
        description = dag_data.get("description")
        initial_step = dag_data.get("initial_step")
        steps = dag_data.get("steps")

        if not name or not initial_step or not steps:
            raise ValueError(f"Invalid DAG YAML structure in {file_path}. 'name', 'initial_step', and 'steps' are required.")

        # Process each step and correlate its logs
        processed_steps = {}
        total_events = 0
        all_mitre_ids = set()
        scenario_dir = os.path.dirname(os.path.abspath(file_path))

        for step_key, step_info in steps.items():
            mitre_technique = step_info.get("mitre_technique")
            log_source = step_info.get("log_source")
            next_transitions = step_info.get("next")

            if not mitre_technique:
                raise ValueError(f"Step '{step_key}' in DAG {name} must specify 'mitre_technique'.")

            all_mitre_ids.add(mitre_technique)
            wazuh_alerts = []

            # If the step defines a log source, load and correlate it
            if log_source:
                resolved_log_path = resolve_log_path(log_source, data_dir=data_dir, scenario_dir=scenario_dir)

                if os.path.exists(resolved_log_path):
                    logger.info("dag_loader.processing_step_logs", step=step_key, log_source=resolved_log_path)

                    loader = self.loader_factory.get_loader_by_path(resolved_log_path)
                    raw_events_gen = loader.load(resolved_log_path)

                    # Correlate events
                    correlated_events = correlate_and_fallback_events(
                        raw_events_gen, [mitre_technique], self.correlation_engine
                    )

                    # Strip information leakage
                    for ev in correlated_events:
                        alert = strip_information_leakage(ev["wazuh_alert"], ev["mitre_technique"])
                        # Retain only necessary fields to save database space inside JSONB
                        wazuh_alerts.append(alert)

                    total_events += len(wazuh_alerts)
                else:
                    logger.warning("dag_loader.log_source_not_found", step=step_key, log_source=log_source)
            else:
                logger.info("dag_loader.step_has_no_logs", step=step_key)

            processed_steps[step_key] = {
                "name": step_info.get("name", step_key.replace("_", " ").title()),
                "mitre_technique": mitre_technique,
                "wazuh_alerts": wazuh_alerts,
                "next": next_transitions,
            }

        dag_structure = {
            "initial_step": initial_step,
            "steps": processed_steps,
        }

        return {
            "name": name,
            "description": description,
            "mitre_ids": list(all_mitre_ids),
            "source_dataset": "custom_dag",
            "source_path": file_path,
            "total_events": total_events,
            "dag_structure": dag_structure,
        }

    def load_all_dags(self, dags_directory: str, data_dir: str = "data") -> list[dict[str, Any]]:
        """
        Loads all DAG scenarios defined in YAML files in the given directory and returns their payloads.
        """
        payloads: list[dict[str, Any]] = []
        if not os.path.exists(dags_directory):
            logger.info("dag_loader.directory_not_found", path=dags_directory)
            return payloads

        files = [
            os.path.join(dags_directory, f)
            for f in os.listdir(dags_directory)
            if f.endswith((".yaml", ".yml"))
        ]

        for file_path in files:
            try:
                payload = self.load_dag_scenario(file_path, data_dir=data_dir)
                payloads.append(payload)
            except Exception as e:
                logger.exception("dag_loader.failed_loading_file", file=file_path, error=str(e))

        return payloads
