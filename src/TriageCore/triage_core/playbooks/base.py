"""
Playbook Base Classes
======================
Defines the data model for SOC playbooks:

  PlaybookStep  – A single response action (tool call or approval gate)
  ApprovalGate  – Requires human confirmation before proceeding
  Playbook      – Ordered list of steps with metadata
  PlaybookContext – Runtime state passed through a playbook execution
  PlaybookResult  – Final outcome returned to the calling agent

Usage (from an MCP tool / agent):
    from triage_core.playbooks import registry
    pb = registry.get("PB-002")
    ctx = PlaybookContext(alert={"agent_id": "007", "src_ip": "10.0.0.1"})
    result = pb.render(ctx)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ─────────────────────────────────────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────────────────────────────────────

class StepStatus(str, Enum):
    PENDING   = "pending"
    APPROVED  = "approved"
    SKIPPED   = "skipped"
    COMPLETED = "completed"
    FAILED    = "failed"


class Severity(str, Enum):
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"

    @property
    def thehive_value(self) -> int:
        return {"low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


# ─────────────────────────────────────────────────────────────────────────────
# PlaybookContext – runtime state / alert data
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PlaybookContext:
    """
    Carries alert / incident data through a playbook execution.

    Attributes:
        alert: Raw alert data dict (e.g. parsed Wazuh event)
        case_id: TheHive case ID once a case has been created
        observables: Dict of observables enriched during the run (ip→score, hash→score…)
        extra: Arbitrary extra context
    """
    alert: dict[str, Any] = field(default_factory=dict)
    case_id: str | None = None
    observables: dict[str, Any] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)

    # Convenience accessors
    @property
    def agent_id(self) -> str:
        return self.alert.get("agent_id", "unknown")

    @property
    def src_ip(self) -> str:
        return self.alert.get("src_ip", "")

    @property
    def agent_name(self) -> str:
        return self.alert.get("agent_name", "unknown")

    @property
    def rule_id(self) -> str:
        return str(self.alert.get("rule_id", ""))

    @property
    def mitre_ids(self) -> list[str]:
        ids = self.alert.get("mitre_ids", [])
        if isinstance(ids, str):
            return [ids]
        return ids


# ─────────────────────────────────────────────────────────────────────────────
# PlaybookStep
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ApprovalGate:
    """
    Represents a human approval checkpoint inside a playbook.
    When the SOC agent encounters this, it MUST stop and ask the operator
    for explicit confirmation before proceeding to the next step.

    Attributes:
        message: What to ask the human operator
        requires_confirmation_for: Short description of the destructive action
    """
    message: str
    requires_confirmation_for: str


@dataclass
class PlaybookStep:
    """
    A single step in a SOC playbook.

    Attributes:
        order: Execution order (0-indexed)
        title: Human-readable step title
        description: Detailed instructions for the SOC agent
        tool_hint: Optional MCP tool name the agent should call for this step
        parameters: Suggested parameters for the tool call (may reference context)
        group: Logical group (Investigation / Enrichment / Containment / Remediation / Reporting)
        approval_gate: If set, agent must request human approval before executing this step
        condition: Optional string expression evaluated against context (not enforced by base class)
    """
    order: int
    title: str
    description: str
    group: str
    tool_hint: str | None = None
    parameters: dict[str, Any] = field(default_factory=dict)
    approval_gate: ApprovalGate | None = None
    condition: str | None = None  # e.g. "src_ip != ''"

    def _interpolate_string(self, text: str, ctx: PlaybookContext) -> str:
        """Interpolates ctx.path placeholders in a string."""
        import re
        
        def repl(match):
            placeholder = match.group(0)
            path = match.group(1)
            parts = path.split(".")
            val: Any = ctx
            for part in parts:
                if isinstance(val, dict):
                    val = val.get(part)
                elif hasattr(val, part):
                    val = getattr(val, part)
                else:
                    return placeholder
            return str(val) if val is not None else ""
            
        return re.sub(r"\bctx\.([a-zA-Z0-9_.]+)", repl, text)

    def is_destructive(self) -> bool:
        """Returns True if this step has a human approval gate."""
        return self.approval_gate is not None

    def render_instruction(self, ctx: PlaybookContext) -> str:
        """
        Returns a natural-language instruction string for the SOC agent,
        with context variables interpolated where possible.
        """
        params_str = ""
        if self.parameters:
            resolved = {}
            for k, v in self.parameters.items():
                if isinstance(v, str) and v.startswith("ctx."):
                    path = v[4:]
                    parts = path.split(".")
                    val: Any = ctx
                    for part in parts:
                        if isinstance(val, dict):
                            val = val.get(part)
                        elif hasattr(val, part):
                            val = getattr(val, part)
                        else:
                            val = v
                            break
                    resolved[k] = val
                else:
                    resolved[k] = v
            params_str = " | ".join(f"{k}={v!r}" for k, v in resolved.items())

        gate_warning = ""
        if self.approval_gate:
            action = self._interpolate_string(self.approval_gate.requires_confirmation_for, ctx)
            ask = self._interpolate_string(self.approval_gate.message, ctx)
            gate_warning = (
                f"\n  ⚠️  **HUMAN APPROVAL REQUIRED BEFORE THIS STEP** ⚠️\n"
                f"  Action: {action}\n"
                f"  Ask: {ask}\n"
                f"  Do NOT proceed until operator explicitly confirms.\n"
            )

        tool_str = f"  Tool: `{self.tool_hint}`" if self.tool_hint else ""
        params_line = f"\n  Parameters: {params_str}" if params_str else ""
        
        title_resolved = self._interpolate_string(self.title, ctx)
        desc_resolved = self._interpolate_string(self.description, ctx)

        return (
            f"**Step {self.order + 1} [{self.group}]: {title_resolved}**\n"
            f"  {desc_resolved}\n"
            f"{tool_str}{params_line}"
            f"{gate_warning}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# PlaybookResult
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PlaybookResult:
    """Returned to the SOC agent when a playbook is triggered."""
    playbook_id: str
    playbook_name: str
    mitre_ids: list[str]
    severity: str
    instructions: str          # Full rendered markdown for the agent
    steps_count: int
    approval_required_steps: list[str]   # titles of steps needing human approval
    case_template: str | None = None  # Template name to use when creating the case
    soar_workflow_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "playbook_id": self.playbook_id,
            "playbook_name": self.playbook_name,
            "mitre_ids": self.mitre_ids,
            "severity": self.severity,
            "steps_count": self.steps_count,
            "approval_required_steps": self.approval_required_steps,
            "case_template": self.case_template,
            "soar_workflow_id": self.soar_workflow_id,
            "instructions": self.instructions,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Playbook
# ─────────────────────────────────────────────────────────────────────────────

class Playbook:
    """
    A structured SOC incident response playbook.

    Args:
        id: Unique playbook identifier (e.g. 'PB-001')
        name: Short human-readable name
        description: What this playbook handles
        mitre_ids: MITRE ATT&CK technique IDs (e.g. ['T1003', 'T1003.008'])
        severity: Incident severity (low / medium / high / critical)
        steps: Ordered list of PlaybookStep instances
        tags: Free-form tags for search/filtering
        case_template: Matching TheHive case template name
        soar_workflow_id: SOAR workflow ID to trigger (if any)
    """

    def __init__(
        self,
        id: str,
        name: str,
        description: str,
        mitre_ids: list[str],
        severity: Severity | str,
        steps: list[PlaybookStep],
        tags: list[str] | None = None,
        case_template: str | None = None,
        soar_workflow_id: str | None = None,
    ) -> None:
        self.id = id
        self.name = name
        self.description = description
        self.mitre_ids = mitre_ids
        self.severity = Severity(severity) if isinstance(severity, str) else severity
        self.steps = sorted(steps, key=lambda s: s.order)
        self.tags = tags or []
        self.case_template = case_template
        self.soar_workflow_id = soar_workflow_id

    def render(self, ctx: PlaybookContext) -> PlaybookResult:
        """
        Renders the playbook into a PlaybookResult for the SOC agent.
        Interpolates context variables into step instructions.
        """
        header = (
            f"# 🛡️ Playbook: {self.name} [{self.id}]\n\n"
            f"**MITRE ATT&CK:** {', '.join(self.mitre_ids)}\n"
            f"**Severity:** {self.severity.value.upper()}\n"
            f"**Agent/Host:** {ctx.agent_name} (ID: {ctx.agent_id})\n"
            f"**Source IP:** {ctx.src_ip or 'N/A'}\n"
            f"**Rule ID:** {ctx.rule_id or 'N/A'}\n\n"
            f"---\n\n"
            f"**Description:** {self.description}\n\n"
            f"---\n\n"
            f"## Response Steps\n\n"
        )

        step_instructions = "\n\n".join(
            step.render_instruction(ctx) for step in self.steps
        )

        approval_steps = [
            step.title for step in self.steps if step.is_destructive()
        ]

        footer = ""
        if self.case_template:
            footer += f"\n\n---\n**📋 TheHive Template:** `{self.case_template}`"
        if self.soar_workflow_id:
            footer += f"\n**⚡ SOAR Workflow:** `{self.soar_workflow_id}`"
        if approval_steps:
            footer += (
                f"\n\n> ⚠️ **{len(approval_steps)} step(s) require human approval** "
                f"before execution:\n"
                + "\n".join(f"> - {t}" for t in approval_steps)
            )

        return PlaybookResult(
            playbook_id=self.id,
            playbook_name=self.name,
            mitre_ids=self.mitre_ids,
            severity=self.severity.value,
            instructions=header + step_instructions + footer,
            steps_count=len(self.steps),
            approval_required_steps=approval_steps,
            case_template=self.case_template,
            soar_workflow_id=self.soar_workflow_id,
        )

    def matches(self, rule_id: str = "", mitre_ids: list[str] | None = None) -> bool:
        """
        Returns True if this playbook is relevant for the given Wazuh rule_id
        or MITRE technique IDs.

        Matching logic (OR between criteria):
        - rule_id: checks ``wazuh-rule-{id}`` convention in playbook tags
        - mitre_ids: prefix/suffix match against playbook's MITRE IDs
        """
        # 1. Rule ID match — tags follow the "wazuh-rule-{id}" convention
        if rule_id:
            rule_tag = f"wazuh-rule-{rule_id}"
            if rule_tag in self.tags:
                return True
            # Also support exact numeric match without prefix (e.g. tags=["100002"])
            if str(rule_id) in self.tags:
                return True

        # 2. MITRE ATT&CK technique ID match
        if mitre_ids:
            for mid in mitre_ids:
                for pb_mid in self.mitre_ids:
                    if mid.upper().startswith(pb_mid.upper()) or pb_mid.upper().startswith(mid.upper()):
                        return True

        return False

    def __repr__(self) -> str:
        return f"<Playbook {self.id}: {self.name} [{', '.join(self.mitre_ids)}]>"
