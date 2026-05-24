import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from soc_mcp.tools.soc_tools import (
    create_case,
    add_case_note,
    update_case_status,
    create_alert,
    get_ip_reputation,
    get_file_reputation,
    get_domain_url_reputation,
    get_ad_user_info,
    query_siem_logs,
    isolate_endpoint,
    get_endpoint_info,
    block_ip,
    disable_user_account,
    trigger_soar_workflow,
)

@pytest.fixture
def mock_registry():
    with patch("soc_mcp.tools.soc_tools.registry") as mock_reg:
        # Mock providers
        mock_case_provider = AsyncMock()
        mock_enrichment_provider = AsyncMock()
        mock_siem_provider = AsyncMock()
        mock_endpoint_provider = AsyncMock()
        mock_firewall_provider = AsyncMock()
        mock_iam_provider = AsyncMock()
        mock_soar_provider = AsyncMock()

        mock_reg.get_case_management_provider.return_value = mock_case_provider
        mock_reg.get_enrichment_provider.return_value = mock_enrichment_provider
        mock_reg.get_siem_provider.return_value = mock_siem_provider
        mock_reg.get_endpoint_provider.return_value = mock_endpoint_provider
        mock_reg.get_firewall_provider.return_value = mock_firewall_provider
        mock_reg.get_iam_provider.return_value = mock_iam_provider
        mock_reg.get_soar_provider.return_value = mock_soar_provider
        
        yield {
            "case": mock_case_provider,
            "enrichment": mock_enrichment_provider,
            "siem": mock_siem_provider,
            "endpoint": mock_endpoint_provider,
            "firewall": mock_firewall_provider,
            "iam": mock_iam_provider,
            "soar": mock_soar_provider,
        }

@pytest.mark.asyncio
async def test_create_case(mock_registry):
    mock_registry["case"].create_case.return_value = "Case ID: 123"
    result = await create_case("Title", "Desc", 3, ["tag1"])
    assert result == "Case ID: 123"
    mock_registry["case"].create_case.assert_called_once_with("Title", "Desc", 3, ["tag1"])

@pytest.mark.asyncio
async def test_query_siem_logs(mock_registry):
    mock_registry["siem"].query_logs.return_value = "Logs found"
    result = await query_siem_logs("rule:123", "last 1h")
    assert result == "Logs found"
    mock_registry["siem"].query_logs.assert_called_once_with("rule:123", "last 1h")

@pytest.mark.asyncio
async def test_get_ip_reputation(mock_registry):
    mock_registry["enrichment"].get_ip_reputation.return_value = "IP Clean"
    result = await get_ip_reputation("1.1.1.1")
    assert result == "IP Clean"
    mock_registry["enrichment"].get_ip_reputation.assert_called_once_with("1.1.1.1")

@pytest.mark.asyncio
async def test_isolate_endpoint(mock_registry):
    mock_registry["endpoint"].isolate_endpoint.return_value = "Isolated"
    result = await isolate_endpoint("001")
    assert result == "Isolated"
    mock_registry["endpoint"].isolate_endpoint.assert_called_once_with("001")

@pytest.mark.asyncio
async def test_trigger_soar_workflow(mock_registry):
    mock_registry["soar"].trigger_workflow.return_value = "Triggered"
    result = await trigger_soar_workflow("wf-1", {"k": "v"})
    assert result == "Triggered"
    mock_registry["soar"].trigger_workflow.assert_called_once_with("wf-1", {"k": "v"}, "")
