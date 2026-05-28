"""
SOC Playbook System
============================
Structured incident response playbooks for Wazuh + Cortex + TheHive + SOAR.
"""
from triage_core.playbooks.base import (
    Playbook,
    PlaybookStep,
    PlaybookResult,
    StepStatus,
    ApprovalGate,
    PlaybookContext,
)
from triage_core.playbooks.registry import PlaybookRegistry

# Auto-register all SOC playbooks on import
import triage_core.playbooks.soc_playbooks  # noqa: F401

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
