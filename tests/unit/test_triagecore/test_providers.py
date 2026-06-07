import os
from pathlib import Path
from unittest.mock import ANY, AsyncMock, MagicMock, patch, mock_open
import pytest

from triage_core.integrations.wazuh import WazuhProvider
from triage_core.integrations.thehive import TheHiveProvider
from triage_core.integrations.cortex import CortexProvider
from triage_core.playbooks.soc_playbooks import PlaybookLoader
from triage_core.playbooks.registry import PlaybookRegistry


def setup_mock_client():
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None
    return mock_client


@pytest.mark.asyncio
async def test_wazuh_provider_timeout_from_env():
    provider = WazuhProvider()
    
    # Mock OS env
    with patch.dict(os.environ, {
        "WAZUH_API_URL": "https://wazuh-manager:55000",
        "WAZUH_API_USER": "test-user",
        "WAZUH_API_PASSWORD": "test-password",
        "WAZUH_API_TIMEOUT": "7.5",
        "WAZUH_API_VERIFY_SSL": "false"
    }):
        mock_client = setup_mock_client()
        
        # Mock authenticate response
        mock_auth_resp = MagicMock()
        mock_auth_resp.json.return_value = {"data": {"token": "mock-token"}}
        mock_client.get.return_value = mock_auth_resp
        
        # Mock active response PUT
        mock_put_resp = MagicMock()
        mock_put_resp.json.return_value = {"status": "ok"}
        mock_client.put.return_value = mock_put_resp
        
        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await provider.isolate_endpoint("agent-123")
            
            assert "agent-123 successfully isolated" in result
            # Assert authentication call was made with timeout=7.5
            mock_client.get.assert_called_once_with(
                "https://wazuh-manager:55000/security/user/authenticate",
                auth=("test-user", "test-password"),
                timeout=7.5
            )
            # Assert active-response call was made with timeout=7.5
            mock_client.put.assert_called_once_with(
                "https://wazuh-manager:55000/active-response",
                json={
                    "command": "host-deny",
                    "custom": False,
                    "agents_list": ["agent-123"]
                },
                headers={"Authorization": "Bearer mock-token"},
                timeout=7.5
            )


@pytest.mark.asyncio
@patch("triage_core.integrations.wazuh.logger")
async def test_wazuh_provider_critical_logs(mock_logger):
    provider = WazuhProvider()
    
    with patch.dict(os.environ, {
        "WAZUH_API_URL": "https://wazuh-manager:55000",
        "WAZUH_API_USER": "test-user",
        "WAZUH_API_PASSWORD": "test-password"
    }):
        mock_client = setup_mock_client()
        mock_client.get.side_effect = Exception("Connection Refused")
        
        with patch("httpx.AsyncClient", return_value=mock_client):
            await provider.isolate_endpoint("agent-123")
            
            # Verify critical logger escalates the error
            mock_logger.critical.assert_called_once_with(
                "wazuh.ar.error",
                error="Connection Refused",
                alert=True,
                containment_failure=True
            )


@pytest.mark.asyncio
@patch("triage_core.integrations.thehive.logger")
async def test_thehive_provider_critical_logs(mock_logger):
    provider = TheHiveProvider()
    
    with patch.dict(os.environ, {
        "THEHIVE_URL": "http://thehive:9000",
        "THEHIVE_API_KEY": "test-api-key"
    }):
        mock_client = setup_mock_client()
        mock_client.post.side_effect = Exception("HTTP 500")
        
        with patch("httpx.AsyncClient", return_value=mock_client):
            await provider.create_case(title="Malicious Activity", description="Detailed description")
            
            mock_logger.critical.assert_called_once_with(
                "thehive.create.error",
                error="HTTP 500",
                alert=True,
                case_mgmt_failure=True
            )


@pytest.mark.asyncio
@patch("triage_core.integrations.cortex.logger")
async def test_cortex_provider_critical_logs(mock_logger):
    provider = CortexProvider()
    
    with patch.dict(os.environ, {
        "CORTEX_URL": "http://localhost:9001",
        "CORTEX_API_KEY": "test-api-key"
    }):
        mock_client = setup_mock_client()
        mock_client.get.side_effect = Exception("Analyzer Unavailable")
        
        with patch("httpx.AsyncClient", return_value=mock_client):
            await provider.get_ip_reputation("8.8.8.8")
            
            # The get_ip_reputation triggers _analyze, which logs critical error on failure
            mock_logger.critical.assert_any_call(
                "cortex.analysis.error",
                error="Analyzer Unavailable",
                alert=True,
                enrichment_failure=True
            )


@patch("triage_core.playbooks.soc_playbooks.logger")
def test_playbook_loader_critical_logs(mock_logger):
    registry = PlaybookRegistry.instance()
    
    with patch("os.scandir") as mock_scandir, \
         patch("pathlib.Path.exists", return_value=True), \
         patch("pathlib.Path.is_dir", return_value=True):
        mock_entry = MagicMock()
        mock_entry.is_file.return_value = True
        mock_entry.name = "malformed_playbook.yaml"
        mock_entry.path = "/fake/path/malformed_playbook.yaml"
        
        mock_scandir.return_value = [mock_entry]
        
        with patch("builtins.open", mock_open(read_data=":- invalid yaml")):
            PlaybookLoader.load_from_directory(Path("/fake/dir"), registry)
            
            mock_logger.critical.assert_called_once_with(
                "playbook_loader.failed_to_load",
                path="/fake/path/malformed_playbook.yaml",
                error=ANY,
                alert=True,
                playbook_failure=True
            )
