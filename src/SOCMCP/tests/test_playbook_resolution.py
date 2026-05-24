import pytest
from soc_mcp.playbooks.base import PlaybookStep, PlaybookContext, ApprovalGate

def test_interpolate_string():
    ctx = PlaybookContext(
        alert={
            "agent_id": "007",
            "agent_name": "wazuh-agent-test",
            "src_ip": "10.0.0.99",
            "username": "attacker_user"
        }
    )
    step = PlaybookStep(
        order=0,
        title="Test ctx.agent_name",
        description="Isolate agent ctx.agent_id",
        group="Investigation"
    )
    
    # Test text interpolation
    assert step._interpolate_string("Agent name: ctx.agent_name", ctx) == "Agent name: wazuh-agent-test"
    assert step._interpolate_string("ID is ctx.agent_id and IP is ctx.src_ip", ctx) == "ID is 007 and IP is 10.0.0.99"
    assert step._interpolate_string("Hello ctx.alert.username", ctx) == "Hello attacker_user"

def test_render_instruction_with_deep_resolution():
    ctx = PlaybookContext(
        alert={
            "agent_id": "007",
            "agent_name": "wazuh-agent-test",
            "src_ip": "10.0.0.99",
            "username": "attacker_user"
        }
    )
    step = PlaybookStep(
        order=0,
        title="Test Step",
        description="Description containing ctx.src_ip",
        group="Investigation",
        tool_hint="disable_user_account",
        parameters={
            "username": "ctx.alert.username",
            "agent_id": "ctx.agent_id"
        },
        approval_gate=ApprovalGate(
            message="Do you want to disable ctx.alert.username?",
            requires_confirmation_for="Disable user account ctx.alert.username"
        )
    )
    
    instruction = step.render_instruction(ctx)
    
    # Verify username parameter is resolved to 'attacker_user'
    assert "username='attacker_user'" in instruction
    assert "agent_id='007'" in instruction
    
    # Verify approval gate fields are interpolated
    assert "Ask: Do you want to disable attacker_user?" in instruction
    assert "Action: Disable user account attacker_user" in instruction
    
    # Verify description is interpolated
    assert "Description containing 10.0.0.99" in instruction
