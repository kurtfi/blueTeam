"""
Unit tests for MCP server tool registration.
"""

from attack_simulator.mcp_server import mcp


import pytest


@pytest.mark.asyncio
async def test_mcp_tools_registration() -> None:
    """
    Verifies that the FastMCP server registers all required simulation tools.
    """
    tools = await mcp.list_tools()
    tool_names = [t.name for t in tools]

    assert "list_simulation_scenarios" in tool_names
    assert "trigger_attack_simulation" in tool_names
    assert "get_simulation_run_status" in tool_names
    assert "get_playbook_coverage_gaps" in tool_names
    assert "activate_scenario" in tool_names
    assert "download_mordor_scenario" in tool_names
