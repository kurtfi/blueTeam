"""
Loads custom YAML/JSON attack scenario definitions.
"""

import os
from typing import Any, Generator
import yaml
import json
import structlog

from attack_simulator.loader.base import DatasetLoader

logger = structlog.get_logger(__name__)


class CustomLoader(DatasetLoader):
    """
    Loads custom attack scenario files (YAML or JSON) containing event templates.
    """

    def __init__(self) -> None:
        self.metadata: dict[str, Any] = {}

    def load_scenario_file(self, filepath: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        """
        Loads the scenario file completely to parse metadata and return the event list.
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Scenario file not found: {filepath}")

        with open(filepath, "r", encoding="utf-8") as f:
            if filepath.endswith(".json"):
                data = json.load(f)
            else:
                data = yaml.safe_load(f)

        self.metadata = {
            "name": data.get("name", "Custom Scenario"),
            "description": data.get("description", ""),
            "mitre_ids": data.get("mitre_ids", []),
            "source_dataset": "custom",
            "source_path": filepath,
        }
        
        events = data.get("events", [])
        return self.metadata, events

    def load(self, source_path: str) -> Generator[dict[str, Any], None, None]:
        """
        Implements the DatasetLoader interface, yielding events.
        """
        try:
            _, events = self.load_scenario_file(source_path)
            for event in events:
                yield event
        except Exception as e:
            logger.error("custom_loader.failed_to_load", path=source_path, error=str(e))
