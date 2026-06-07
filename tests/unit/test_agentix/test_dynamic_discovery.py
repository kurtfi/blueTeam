import pytest
from agentic_common.base_tool import BaseTool
from agentix.core.prompt_composer import SystemPromptComposer
from agentix.registry.catalog import ToolCatalog


class DummyTool(BaseTool):
    def __init__(self, name: str, description: str, category: str = "data"):
        self._name = name
        self._description = description
        self.category = category

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return self._description

    @property
    def parameters(self) -> dict:
        return {}

    async def execute(self, **kwargs):
        return None


@pytest.mark.asyncio
async def test_tool_selection_without_names():
    catalog = ToolCatalog()
    tool1 = DummyTool("tool1", "Description 1")
    tool2 = DummyTool("tool2", "Description 2")
    catalog.register(tool1)
    catalog.register(tool2)

    # Empty name_filter should return all registered tools
    selected = await catalog.select(user_message="test message", name_filter=[], use_semantic_search=False)
    assert len(selected) == 2
    assert selected[0].name == "tool1"
    assert selected[1].name == "tool2"


@pytest.mark.asyncio
async def test_tool_selection_with_allowlist():
    catalog = ToolCatalog()
    tool1 = DummyTool("tool1", "Description 1")
    tool2 = DummyTool("tool2", "Description 2")
    tool3 = DummyTool("tool3", "Description 3")
    catalog.register(tool1)
    catalog.register(tool2)
    catalog.register(tool3)

    # name_filter restricts returned tools to allowlisted ones
    selected = await catalog.select(
        user_message="test message", name_filter=["tool1", "tool3"], use_semantic_search=False
    )
    assert len(selected) == 2
    assert {t.name for t in selected} == {"tool1", "tool3"}


@pytest.mark.asyncio
async def test_tool_selection_with_exclude_names():
    catalog = ToolCatalog()
    tool1 = DummyTool("tool1", "Description 1")
    tool2 = DummyTool("tool2", "Description 2")
    catalog.register(tool1)
    catalog.register(tool2)

    # exclude_names should remove those tools from selection
    selected = await catalog.select(
        user_message="test message", name_filter=[], exclude_names=["tool1"], use_semantic_search=False
    )
    assert len(selected) == 1
    assert selected[0].name == "tool2"


def test_prompt_injection_tools():
    composer = SystemPromptComposer("System Prompt Base")

    tool1 = DummyTool("tool1", "Description 1")
    tool2 = DummyTool("tool2", "Description 2\nwith newline")

    prompt = composer.compose(available_tools=[tool1, tool2])

    assert "System Prompt Base" in prompt
    assert "### Available Tools (Dynamic)" in prompt
    assert "- **tool1**: Description 1" in prompt
    assert "- **tool2**: Description 2 with newline" in prompt  # Newline should be cleaned


def test_prompt_injection_playbooks():
    composer = SystemPromptComposer("SOC Analyst Base")

    # Has playbook tool, so playbooks should be injected
    playbook_tool = DummyTool("trigger_playbook", "Trigger SOC playbook")
    playbooks_str = "PB-001 - Ransomware\nPB-002 - Phishing"

    prompt = composer.compose(available_tools=[playbook_tool], playbooks_str=playbooks_str)

    assert "SOC Analyst Base" in prompt
    assert "### Available Playbooks (Dynamic)" in prompt
    assert "PB-001 - Ransomware" in prompt
    assert "PB-002 - Phishing" in prompt


def test_prompt_injection_no_playbooks_for_restricted_agents():
    composer = SystemPromptComposer("Threat Intel Base")

    # Only has reputation tool (no playbook tools), playbooks should NOT be injected
    rep_tool = DummyTool("get_ip_reputation", "Get IP reputation")
    playbooks_str = "PB-001 - Ransomware\nPB-002 - Phishing"

    prompt = composer.compose(available_tools=[rep_tool], playbooks_str=playbooks_str)

    assert "Threat Intel Base" in prompt
    assert "### Available Playbooks (Dynamic)" not in prompt
    assert "PB-001 - Ransomware" not in prompt
