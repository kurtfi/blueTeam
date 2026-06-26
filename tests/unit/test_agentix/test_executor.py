import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from agentix.sandbox.executor import run_command


@pytest.mark.asyncio
async def test_run_command_sandbox_disabled():
    with patch("agentix.sandbox.executor.settings") as mock_settings:
        mock_settings.agentix_sandbox_enabled = False
        res = await run_command("echo hello")
        assert res.success is False
        assert "Sandbox is disabled" in res.error


@pytest.mark.asyncio
async def test_run_command_empty():
    with patch("agentix.sandbox.executor.settings") as mock_settings:
        mock_settings.agentix_sandbox_enabled = True
        res = await run_command("")
        assert res.success is False
        assert "Empty command" in res.error


@pytest.mark.asyncio
async def test_run_command_success():
    with (
        patch("agentix.sandbox.executor.settings") as mock_settings,
        patch("agentix.sandbox.executor.asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec,
    ):
        mock_settings.agentix_sandbox_enabled = True

        proc_mock = MagicMock()
        proc_mock.returncode = 0
        proc_mock.communicate = AsyncMock(return_value=(b"hello world\n", b""))
        mock_exec.return_value = proc_mock

        res = await run_command("echo 'hello world'")

        assert res.success is True
        assert res.output == "hello world\n"
        mock_exec.assert_called_once_with(
            "echo", "hello world", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, process_group=0
        )


@pytest.mark.asyncio
async def test_run_command_failure():
    with (
        patch("agentix.sandbox.executor.settings") as mock_settings,
        patch("agentix.sandbox.executor.asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec,
    ):
        mock_settings.agentix_sandbox_enabled = True

        proc_mock = MagicMock()
        proc_mock.returncode = 1
        proc_mock.communicate = AsyncMock(return_value=(b"", b"command not found\n"))
        mock_exec.return_value = proc_mock

        res = await run_command("some_invalid_cmd")

        assert res.success is False
        assert "Exit code 1" in res.error
        assert "command not found" in res.error


@pytest.mark.asyncio
async def test_run_command_timeout():
    import signal
    with (
        patch("agentix.sandbox.executor.settings") as mock_settings,
        patch("agentix.sandbox.executor.asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec,
        patch("agentix.sandbox.executor.asyncio.wait_for", new_callable=AsyncMock) as mock_wait,
        patch("agentix.sandbox.executor.os.killpg") as mock_killpg,
    ):
        mock_settings.agentix_sandbox_enabled = True

        proc_mock = MagicMock()
        proc_mock.pid = 12345
        proc_mock.communicate = AsyncMock(return_value=(b"", b""))
        mock_exec.return_value = proc_mock

        mock_wait.side_effect = TimeoutError()

        res = await run_command("sleep 10", timeout=2)

        assert res.success is False
        assert "Command timed out" in res.error
        mock_killpg.assert_called_once_with(12345, signal.SIGKILL)
