"""
SOC Playbook System
============================
Structured incident response playbooks for Wazuh + Cortex + TheHive + Shuffle.
"""
from soc_mcp.playbooks.base import (
    Playbook,
    PlaybookStep,
    PlaybookResult,
    StepStatus,
    ApprovalGate,
    PlaybookContext,
)
from soc_mcp.playbooks.registry import PlaybookRegistry

# Auto-register all SOC playbooks on import
import soc_mcp.playbooks.soc_playbooks  # noqa: F401

registry = PlaybookRegistry.instance()

__all__ = [
    "Playbook",
    "PlaybookStep",
    "PlaybookResult",
    "StepStatus",
    "ApprovalGate",
    "PlaybookContext",
    "PlaybookRegistry",
    "registry",
]
