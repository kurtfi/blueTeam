"""
Unit and integration tests for the refactored AttackSimulator components.
"""

import json
import os
import tempfile
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from attack_simulator.evaluator.agentix_gateway import AgentixSessionGateway
from attack_simulator.sender.factory import get_sender
from attack_simulator.sender.file import FileAlertSender
from attack_simulator.sender.syslog import SyslogAlertSender
from attack_simulator.services.timing import ConstantDelayStrategy, OriginalDeltaStrategy


@pytest.mark.asyncio
async def test_file_alert_sender() -> None:
    """Verifies that FileAlertSender writes serialized JSON alerts to a file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = os.path.join(tmpdir, "test_alerts.log")
        sender = FileAlertSender(file_path=log_path)

        payload = {
            "rule": {"id": "1001", "level": 5, "description": "Test Alert", "groups": ["test"]},
            "full_log": "Sysmon process dump test",
        }

        session_id = await sender.send(payload, "T1003")
        assert session_id is not None
        assert os.path.exists(log_path)

        with open(log_path, encoding="utf-8") as f:
            lines = f.readlines()
            assert len(lines) == 1
            data = json.loads(lines[0])
            assert data["simulation_session_id"] == session_id
            assert "mitre" not in data["rule"]  # Leakage stripped


@pytest.mark.asyncio
async def test_syslog_alert_sender_rfc5424() -> None:
    """Verifies that SyslogAlertSender formats RFC 5424 correctly."""
    sender = SyslogAlertSender(host="localhost", port=1514, protocol="UDP", rfc5424=True)
    payload = {
        "@timestamp": "2026-06-22T23:12:48.123Z",
        "agent": {"name": "test-host"},
        "rule": {"id": "1002", "level": 10, "description": "AD Replication", "groups": ["windows"]},
        "full_log": "Test AD Replication",
    }

    formatted = sender._format_rfc5424(payload, "T1003.006")
    assert formatted.startswith("<134>1 ")
    # Check timestamp replacement: Z should be replaced by +00:00
    assert " 2026-06-22T23:12:48.123+00:00 " in formatted
    assert " test-host AttackSimulator " in formatted
    assert " 1002 - " in formatted
    assert formatted.endswith(json.dumps(payload))


@pytest.mark.asyncio
async def test_syslog_alert_sender_transmission() -> None:
    """Verifies UDP syslog sending transmission logic using a mocked socket."""
    sender = SyslogAlertSender(host="127.0.0.1", port=1514, protocol="UDP", rfc5424=False)
    payload = {"full_log": "Log content"}

    with patch("socket.socket") as mock_socket:
        mock_sock_inst = MagicMock()
        mock_sock_inst.__enter__.return_value = mock_sock_inst
        mock_socket.return_value = mock_sock_inst

        session_id = await sender.send(payload, "T1059")
        assert session_id is not None
        assert mock_sock_inst.sendto.called


@pytest.mark.asyncio
async def test_sender_factory() -> None:
    """Verifies the sender factory retrieves correct classes."""
    sender = get_sender("file", file_path="data/test.log")
    assert isinstance(sender, FileAlertSender)
    assert sender.file_path.endswith("data/test.log")

    sender_syslog = get_sender("syslog", syslog_host="10.0.0.1", syslog_port=514)
    assert isinstance(sender_syslog, SyslogAlertSender)
    assert sender_syslog.host == "10.0.0.1"

    sender_default = get_sender("unknown")
    from attack_simulator.sender.webhook import WebhookAlertSender

    assert isinstance(sender_default, WebhookAlertSender)


@pytest.mark.asyncio
async def test_constant_delay_strategy() -> None:
    """Verifies ConstantDelayStrategy sleeps correctly."""
    strategy = ConstantDelayStrategy(delay_seconds=0.01)
    with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
        await strategy.wait_before_next({}, {})
        mock_sleep.assert_called_once_with(0.01)


@pytest.mark.asyncio
async def test_original_delta_strategy() -> None:
    """Verifies OriginalDeltaStrategy calculates and caps the delta time."""
    strategy = OriginalDeltaStrategy(default_delay=1.0, max_delay=30.0)

    # 1. Delta within cap (e.g. 5 seconds)
    ev1 = {"wazuh_alert": {"@timestamp": "2026-06-22T23:00:00.000Z"}}
    ev2 = {"wazuh_alert": {"@timestamp": "2026-06-22T23:00:05.000Z"}}

    with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
        await strategy.wait_before_next(ev1, ev2)
        mock_sleep.assert_called_once_with(5.0)

    # 2. Delta exceeding cap (e.g. 60 seconds -> capped to 30.0)
    ev3 = {"wazuh_alert": {"@timestamp": "2026-06-22T23:01:00.000Z"}}
    with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
        await strategy.wait_before_next(ev1, ev3)
        mock_sleep.assert_called_once_with(30.0)

    # 3. Missing timestamps fallback
    with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
        await strategy.wait_before_next({}, {})
        mock_sleep.assert_called_once_with(1.0)


@pytest.mark.asyncio
async def test_agentix_session_gateway() -> None:
    """Verifies AgentixSessionGateway functions query the Agentix HTTP APIs correctly."""
    import httpx

    gateway = AgentixSessionGateway()
    dummy_session_id = str(uuid.uuid4())

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None

    # Mock responses
    mock_status_response = MagicMock(spec=httpx.Response)
    mock_status_response.status_code = 200
    mock_status_response.json.return_value = {"status": "ACTIVE"}

    mock_events_response = MagicMock(spec=httpx.Response)
    mock_events_response.status_code = 200
    mock_events_response.json.return_value = [
        {"event_type": "think", "actor": "agent", "content": "thought", "metadata": None}
    ]

    with patch("httpx.AsyncClient", return_value=mock_client):
        # Configure mock get requests
        mock_client.get.side_effect = [mock_status_response, mock_events_response]

        status = await gateway.get_session_status(dummy_session_id)
        assert status == "ACTIVE"

        events = await gateway.get_session_events(dummy_session_id)
        assert len(events) == 1
        assert events[0]["event_type"] == "think"
