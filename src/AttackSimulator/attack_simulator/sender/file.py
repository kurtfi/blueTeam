"""
File client to write correlated alerts to a local log file.
"""

import json
import os
import uuid
from typing import Any

import structlog

from attack_simulator.mapper.wazuh_template import strip_information_leakage
from attack_simulator.sender.base import AlertSender

logger = structlog.get_logger(__name__)


class FileAlertSender(AlertSender):
    """
    Alert sender implementation that writes payloads to a local log file.
    """

    def __init__(self, file_path: str | None = None) -> None:
        if file_path is None:
            # Default simulation output path
            file_path = os.getenv("ATTACK_SIMULATOR_FILE_PATH", "data/simulation_alerts.log")
        self.file_path = os.path.abspath(file_path)

    async def send(self, alert_payload: dict[str, Any], technique_id: str) -> str | None:
        # Safeguard: strip any information leakage
        clean_payload = strip_information_leakage(alert_payload, technique_id)

        try:
            os.makedirs(os.path.dirname(self.file_path), exist_ok=True)

            logger.debug(
                "sender.writing_to_file",
                file=self.file_path,
                rule_id=clean_payload.get("rule", {}).get("id"),
            )

            # Generate a dummy session ID to simulate a SIEM session creation
            dummy_session_id = str(uuid.uuid4())
            clean_payload["simulation_session_id"] = dummy_session_id

            with open(self.file_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(clean_payload) + "\n")

            logger.info("sender.file_write_successful", session_id=dummy_session_id, path=self.file_path)
            return dummy_session_id

        except Exception as e:
            logger.error("sender.file_write_error", path=self.file_path, error=str(e))
            return None
