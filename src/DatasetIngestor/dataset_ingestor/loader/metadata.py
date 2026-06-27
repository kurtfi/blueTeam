"""
Extracts scenario metadata from Mordor or Custom datasets.
"""

import json
import os
from typing import Any
import yaml

from dataset_ingestor.mapper.mordor_filename import extract_technique_from_path, get_mordor_file_info


class ScenarioMetadataReader:
    """
    Reader to parse metadata information (name, description, MITRE IDs) from scenario files.
    """

    @staticmethod
    def read_metadata(filepath: str, source_type: str) -> dict[str, Any]:
        """
        Parses the scenario metadata depending on its source type.
        """
        if source_type == "mordor":
            filename = os.path.basename(filepath)
            info = get_mordor_file_info(filename)
            if info:
                mitre_ids = info.get("techniques", [])
            else:
                mitre_ids = [extract_technique_from_path(filepath)]

            resolved_name = (
                os.path.splitext(filename)[0].replace("_", " ").title()
            )
            resolved_desc = f"Simulated attack using Mordor dataset: {filename}"

            return {
                "name": resolved_name,
                "description": resolved_desc,
                "mitre_ids": mitre_ids,
            }

        else:  # custom
            if not os.path.exists(filepath):
                raise FileNotFoundError(f"Scenario file not found: {filepath}")

            with open(filepath, encoding="utf-8") as f:
                if filepath.endswith(".json"):
                    data = json.load(f)
                else:
                    data = yaml.safe_load(f)

            return {
                "name": data.get("name", "Custom Scenario"),
                "description": data.get("description", ""),
                "mitre_ids": data.get("mitre_ids", []),
            }
