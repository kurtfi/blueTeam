"""
Loads custom YAML/JSON attack scenario definitions.
"""

import json
import os
from collections.abc import Generator
from typing import Any

import structlog
import yaml
from dataset_ingestor.loader.base import DatasetLoader

logger = structlog.get_logger(__name__)


class CustomLoader(DatasetLoader):
    """
    Loads custom attack scenario files (YAML or JSON) containing event templates.
    """

    def load(self, source_path: str) -> Generator[dict[str, Any], None, None]:
        """
        Implements the DatasetLoader interface, yielding events.
        """
        if not os.path.exists(source_path):
            logger.error("custom_loader.file_not_found", path=source_path)
            return

        try:
            with open(source_path, encoding="utf-8") as f:
                if source_path.endswith(".json"):
                    data = json.load(f)
                else:
                    data = yaml.safe_load(f)

            events = data.get("events", [])
            yield from events
        except Exception as e:
            logger.error("custom_loader.failed_to_load", path=source_path, error=str(e))
            return
