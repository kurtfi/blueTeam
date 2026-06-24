"""
Memory-efficient streaming reader for Mordor ZIP/JSONL files.
"""

import json
import os
import zipfile
from collections.abc import Generator
from typing import Any

import structlog
from dataset_ingestor.loader.base import DatasetLoader

logger = structlog.get_logger(__name__)


class MordorLoader(DatasetLoader):
    """
    Loads raw security events from a Mordor ZIP file without extracting to disk.
    """

    def load(self, source_path: str) -> Generator[dict[str, Any], None, None]:
        if not os.path.exists(source_path):
            logger.error("mordor_loader.file_not_found", path=source_path)
            return

        logger.info("mordor_loader.start_loading", path=source_path, size_bytes=os.path.getsize(source_path))

        try:
            with zipfile.ZipFile(source_path, "r") as z:
                # Find the first JSON file in the zip archive
                json_files = [name for name in z.namelist() if name.endswith(".json")]
                if not json_files:
                    logger.error("mordor_loader.no_json_file_in_zip", path=source_path)
                    return

                target_file = json_files[0]
                logger.info("mordor_loader.streaming_file", archive_file=target_file)

                # Open the JSON file in streaming mode
                with z.open(target_file, "r") as f:
                    # Let's read line by line to keep memory footprint extremely small
                    line_count = 0
                    for line_bytes in f:
                        line = line_bytes.decode("utf-8").strip()
                        if not line:
                            continue

                        # Clean JSON array syntax elements (e.g. [, ], trailing commas)
                        if line == "[" or line == "]":
                            continue

                        if line.endswith(","):
                            line = line[:-1].strip()

                        if line.endswith("]"):
                            # This handles the last object in a JSON array: "}" + "]"
                            line = line[:-1].strip()

                        try:
                            # Parse a single event
                            event_data = json.loads(line)
                            if isinstance(event_data, dict):
                                line_count += 1
                                yield event_data
                        except json.JSONDecodeError:
                            # If line-by-line parsing fails, it might be a small minified array.
                            # Fallback if line count is 0 and it looks like a single-line array.
                            if line_count == 0 and line.startswith("[") and line.endswith("]"):
                                try:
                                    all_data = json.loads(line)
                                    if isinstance(all_data, list):
                                        for item in all_data:
                                            if isinstance(item, dict):
                                                line_count += 1
                                                yield item
                                except Exception as inner_e:
                                    logger.error("mordor_loader.inner_parse_error", error=str(inner_e))
                            continue

                    logger.info("mordor_loader.completed", total_events_read=line_count)

        except Exception as e:
            logger.error("mordor_loader.failed_to_read_zip", path=source_path, error=str(e))
