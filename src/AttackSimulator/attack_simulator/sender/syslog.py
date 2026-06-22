"""
Syslog client to send correlated alerts to a syslog server over UDP or TCP.
Supports standard RFC 5424 framing.
"""

import json
import os
import socket
import uuid
from datetime import UTC, datetime
from typing import Any

import structlog
from attack_simulator.mapper.wazuh_template import strip_information_leakage
from attack_simulator.sender.base import AlertSender

logger = structlog.get_logger(__name__)


class SyslogAlertSender(AlertSender):
    """
    Alert sender implementation that forwards payloads to a syslog daemon.
    """

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        protocol: str | None = None,
        rfc5424: bool = True,
    ) -> None:
        self.host = host or os.getenv("ATTACK_SIMULATOR_SYSLOG_HOST", "localhost")
        self.port = port or int(os.getenv("ATTACK_SIMULATOR_SYSLOG_PORT", "514"))
        self.protocol = (protocol or os.getenv("ATTACK_SIMULATOR_SYSLOG_PROTOCOL", "UDP")).upper()
        self.rfc5424 = rfc5424

    def _format_rfc5424(self, payload: dict[str, Any], technique_id: str) -> str:
        """
        Formats the message to comply with RFC 5424 standard:
        <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
        """
        # PRI: Facility * 8 + Severity. Default to local0 (16) * 8 + Info (6) = 134
        pri = 134
        version = 1
        timestamp = payload.get("@timestamp") or datetime.now(UTC).isoformat()
        # Replace Z with +00:00 for strict RFC 5424 parsing in some tools
        if timestamp.endswith("Z"):
            timestamp = timestamp[:-1] + "+00:00"

        hostname = payload.get("agent", {}).get("name", "client-workstation-01")
        app_name = "AttackSimulator"
        procid = os.getpid()
        msgid = payload.get("rule", {}).get("id", "-")
        structured_data = "-"  # We put JSON details in MSG instead of structured data

        # The message body is the clean serialized alert JSON
        msg = json.dumps(payload)

        return f"<{pri}>{version} {timestamp} {hostname} {app_name} {procid} {msgid} {structured_data} {msg}"

    async def send(self, alert_payload: dict[str, Any], technique_id: str) -> str | None:
        # Safeguard: strip information leakage
        clean_payload = strip_information_leakage(alert_payload, technique_id)

        # Generate a dummy session ID to simulate session tracking
        dummy_session_id = str(uuid.uuid4())
        clean_payload["simulation_session_id"] = dummy_session_id

        # Format message
        if self.rfc5424:
            msg = self._format_rfc5424(clean_payload, technique_id)
        else:
            msg = json.dumps(clean_payload)

        # Add newline separator for TCP framing or general cleanliness
        msg_bytes = (msg + "\n").encode("utf-8")

        logger.debug(
            "sender.sending_syslog",
            host=self.host,
            port=self.port,
            protocol=self.protocol,
            rfc5424=self.rfc5424,
            rule_id=clean_payload.get("rule", {}).get("id"),
        )

        try:
            if self.protocol == "TCP":
                # TCP Connection (Synchronous socket connection wrapped inside thread pool is safest,
                # or standard socket with a small timeout for simulation purposes)
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(2.0)
                    s.connect((self.host, self.port))
                    s.sendall(msg_bytes)
            else:  # UDP
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(2.0)
                    s.sendto(msg_bytes, (self.host, self.port))

            logger.info("sender.syslog_sent_successfully", session_id=dummy_session_id, host=self.host, port=self.port)
            return dummy_session_id

        except Exception as e:
            logger.error("sender.syslog_send_error", host=self.host, port=self.port, error=str(e))
            # Even if transmission fails, we return the dummy session ID so the run isn't blocked,
            # but we log it as error.
            return dummy_session_id
