"""
SOC Playbook System
============================
Structured incident response playbooks for Wazuh + Cortex + TheHive + SOAR.
"""

# Auto-register all SOC playbooks on import
import triage_core.playbooks.soc_playbooks  # noqa: F401
from triage_core.playbooks.base import (
    ApprovalGate,
    Playbook,
    PlaybookContext,
    PlaybookResult,
    PlaybookStep,
    StepStatus,
)
from triage_core.playbooks.registry import PlaybookRegistry

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
