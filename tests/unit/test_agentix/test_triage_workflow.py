from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from agentix.core.triage_workflow import process_siem_alert, set_shared_catalog


@pytest.mark.asyncio
async def test_process_siem_alert_no_catalog():
    # If shared catalog is not set, it should return early
    set_shared_catalog(None)
    
    with patch("agentix.core.triage_workflow.asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
        await process_siem_alert("sess_1", {"rule": "123"})
        mock_sleep.assert_called_once_with(15)

@pytest.mark.asyncio
async def test_process_siem_alert_success():
    from unittest.mock import ANY
    catalog_mock = MagicMock()
    catalog_mock.all_tools.return_value = ["tool1", "tool2"]
    set_shared_catalog(catalog_mock)
    
    with patch("agentix.core.triage_workflow.asyncio.sleep", new_callable=AsyncMock) as mock_sleep, \
         patch("agentix.core.triage_workflow.AgentFactory.create") as mock_factory, \
         patch("agentix.core.triage_workflow.postgres_session_repo") as mock_repo:
        
        # Mock Orchestrator and run_stream
        orchestrator_mock = MagicMock()
        mock_factory.return_value = orchestrator_mock
        
        step_mock = MagicMock()
        step_mock.step_type.value = "tool"
        step_mock.content = "Doing stuff"
        step_mock.tool_name = "test_tool"
        
        async def mock_run_stream(*args, **kwargs):
            yield step_mock
            
        orchestrator_mock.run_stream = mock_run_stream
        
        await process_siem_alert("sess_2", {"rule": "456"})
        
        mock_sleep.assert_called_once_with(15)
        mock_factory.assert_called_once_with("soc_analyst", catalog=catalog_mock, memory=ANY)
