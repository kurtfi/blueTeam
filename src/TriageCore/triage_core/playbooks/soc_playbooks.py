"""
SOC Playbook Definitions
=========================
Dynamically loads and registers playbooks from YAML definition files.
Conforms to OCP by allowing new playbooks to be added without modifying code.
"""

from __future__ import annotations

import os
from pathlib import Path

import structlog
import yaml

from triage_core.playbooks.base import (
    ApprovalGate,
    Playbook,
    PlaybookStep,
    Severity,
)
from triage_core.playbooks.registry import PlaybookRegistry

logger = structlog.get_logger(__name__)


class PlaybookLoader:
    """
    Service responsible for loading declarative YAML playbooks
    and registering them with the registry (SRP).
    """

    @staticmethod
    def load_from_directory(directory: Path, registry: PlaybookRegistry) -> None:
        """
        Scans directory for .yaml/.yml files, parses them,
        instantiates Playbooks, and registers them.
        """
        if not directory.exists() or not directory.is_dir():
            logger.warning("playbook_loader.directory_not_found", path=str(directory))
            return

        loaded_count = 0
        for entry in os.scandir(directory):
            if entry.is_file() and entry.name.endswith((".yaml", ".yml")):
                try:
                    with open(entry.path, encoding="utf-8") as f:
                        data = yaml.safe_load(f)

                    if not data:
                        continue

                    # Extract relative path from src/ for registration
                    idx = entry.path.find("src/")
                    rel_path = entry.path[idx:] if idx != -1 else entry.path

                    playbook = PlaybookLoader.parse_playbook(data, file_path=rel_path)
                    registry.register(playbook)
                    loaded_count += 1
                    logger.debug("playbook_loader.loaded", playbook_id=playbook.id, path=entry.path)
                except Exception as e:
                    logger.critical(
                        "playbook_loader.failed_to_load",
                        path=entry.path,
                        error=str(e),
                        alert=True,
                        playbook_failure=True,
                    )

        logger.info("playbook_loader.completed", loaded_count=loaded_count, directory=str(directory))

    @staticmethod
    def parse_playbook(data: dict, file_path: str | None = None) -> Playbook:
        """
        Parses a playbook dictionary into a concrete Playbook instance.
        """
        pb_id = data["id"]
        name = data["name"]
        description = data["description"]
        mitre_ids = data["mitre_ids"]
        severity = Severity(data["severity"].lower())
        tags = data.get("tags", [])
        case_template = data.get("case_template")
        soar_workflow_id = data.get("soar_workflow_id")

        steps = []
        for step_data in data.get("steps", []):
            approval_gate = None
            gate_data = step_data.get("approval_gate")
            if gate_data:
                approval_gate = ApprovalGate(
                    message=gate_data["message"], requires_confirmation_for=gate_data["requires_confirmation_for"]
                )

            step = PlaybookStep(
                order=int(step_data["order"]),
                title=step_data["title"],
                group=step_data["group"],
                description=step_data["description"],
                tool_hint=step_data.get("tool_hint"),
                parameters=step_data.get("parameters", {}),
                approval_gate=approval_gate,
                condition=step_data.get("condition"),
            )
            steps.append(step)

        return Playbook(
            id=pb_id,
            name=name,
            description=description,
            mitre_ids=mitre_ids,
            severity=severity,
            steps=steps,
            tags=tags,
            case_template=case_template,
            soar_workflow_id=soar_workflow_id,
            file_path=file_path,
        )


# Register all playbooks automatically on module load (preserving backwards compatibility)
_registry = PlaybookRegistry.instance()
_definitions_dir = Path(__file__).resolve().parent / "definitions"
PlaybookLoader.load_from_directory(_definitions_dir, _registry)
