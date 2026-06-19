import sys
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from agentic_common.base_tool import ToolResult
from agentix.core.orchestrator import Orchestrator
from agentix.tools.mcp_adapter import MCPToolAdapter
from agentix.agents.schema import AgentConfig, ToolFilter

# Add src/Agentix and src/AgenticCommon to sys.path
root_dir = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(root_dir / "src" / "Agentix"))
sys.path.insert(0, str(root_dir / "src" / "AgenticCommon"))


@pytest.mark.asyncio
async def test_orchestrator_playbook_filtering_allowed():
    # Mock database repo
    db_repo_mock = AsyncMock()
    db_repo_mock.get_allowed_playbooks_for_agent.return_value = ["PB-001"]

    # Mock catalog
    catalog_mock = MagicMock()
    catalog_mock.cached_playbooks_json = json.dumps([
        {"id": "PB-001", "name": "Shadow Access", "mitre_ids": ["T1003"], "severity": "high", "steps": 5},
        {"id": "PB-002", "name": "Brute Force", "mitre_ids": ["T1110"], "severity": "medium", "steps": 3},
    ])

    # Tool mapping with playbook tool
    tool_mock = MagicMock()
    tool_mock.name = "trigger_playbook"
    tool_mock.to_openai_schema.return_value = {"name": "trigger_playbook"}
    catalog_mock.select = AsyncMock(return_value=[tool_mock])

    # Agent config
    config = AgentConfig(
        id="soc_analyst",
        name="SOC Analyst",
        role="Expert incident responder",
        tool_filters=ToolFilter(names=["trigger_playbook"]),
        max_iterations=1,
    )

    orch = Orchestrator(
        catalog=catalog_mock,
        db_repo=db_repo_mock,
        config=config,
    )

    with patch("agentix.core.rag.ContextEnrichmentService.retrieve_context", new_callable=AsyncMock) as mock_rag:
        mock_rag.return_value = "Mock RAG"
        
        # Call internal context setup
        res = await orch._setup_orchestrator_context(
            user_message="Triage PB-001",
            user_id="user-123",
            history=[],
            log=MagicMock(),
        )

        assert res is not None
        messages, _, _ = res
        system_prompt = messages[0]["content"]

        # PB-001 is allowed, so it should be injected in prompt
        assert "Shadow Access" in system_prompt
        # PB-002 is not allowed, so it should NOT be in prompt
        assert "Brute Force" not in system_prompt

        db_repo_mock.get_allowed_playbooks_for_agent.assert_called_once_with("soc_analyst")


@pytest.mark.asyncio
async def test_orchestrator_no_playbook_tools_no_db_query():
    # Mock database repo
    db_repo_mock = AsyncMock()

    # Mock catalog without playbook tools
    catalog_mock = MagicMock()
    tool_mock = MagicMock()
    tool_mock.name = "query_siem_logs"
    tool_mock.to_openai_schema.return_value = {"name": "query_siem_logs"}
    catalog_mock.select = AsyncMock(return_value=[tool_mock])

    config = AgentConfig(
        id="log_analyst",
        name="Log Analyst",
        role="Log reader",
        tool_filters=ToolFilter(names=["query_siem_logs"]),
        max_iterations=1,
    )

    orch = Orchestrator(
        catalog=catalog_mock,
        db_repo=db_repo_mock,
        config=config,
    )

    with patch("agentix.core.rag.ContextEnrichmentService.retrieve_context", new_callable=AsyncMock) as mock_rag:
        mock_rag.return_value = "Mock RAG"

        res = await orch._setup_orchestrator_context(
            user_message="Check logs",
            user_id="user-123",
            history=[],
            log=MagicMock(),
        )

        assert res is not None
        db_repo_mock.get_allowed_playbooks_for_agent.assert_not_called()


@pytest.mark.asyncio
@patch("agentic_common.memory.postgres_session.postgres_session_repo.get_allowed_playbooks_for_agent", new_callable=AsyncMock)
async def test_mcp_adapter_authorization_check(mock_get_allowed):
    # Mock fastmcp client
    client_mock = AsyncMock()
    client_mock.call_tool.return_value = "Playbook triggered"

    adapter = MCPToolAdapter(
        name="trigger_playbook",
        description="Trigger playbook",
        parameters={"properties": {}},
        client=client_mock,
    )

    # 1. Unauthorized case
    mock_get_allowed.return_value = ["PB-001", "PB-002"]
    ctx = {"agent_id": "soc_analyst"}

    res = await adapter.execute(context=ctx, playbook_id="PB-003")
    assert not res.success
    assert "Unauthorized" in res.error
    client_mock.call_tool.assert_not_called()

    # 2. Authorized case
    res2 = await adapter.execute(context=ctx, playbook_id="PB-001")
    assert res2.success
    assert res2.output == "Playbook triggered"
    client_mock.call_tool.assert_called_once_with("trigger_playbook", arguments={"playbook_id": "PB-001"})


def test_simulation_analyst_loading():
    from agentix.agents.loader import AgentLoader
    config = AgentLoader.load_by_name("simulation_analyst")
    assert config.id == "simulation_analyst"
    assert config.name == "Simulation Analyst"
    assert "find_playbook_for_alert" in config.system_prompt_override
