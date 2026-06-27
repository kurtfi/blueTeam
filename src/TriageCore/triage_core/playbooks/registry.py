"""
Playbook Registry
==================
Singleton registry that stores and retrieves Playbook instances.

Usage:
    registry = PlaybookRegistry.instance()
    registry.register(my_playbook)
    pb = registry.get("PB-001")
    candidates = registry.find_for_alert(rule_id="100002", mitre_ids=["T1003.008"])
"""

from __future__ import annotations

import threading

from triage_core.playbooks.base import Playbook, PlaybookContext, PlaybookResult


class PlaybookRegistry:
    """Thread-safe singleton that holds all registered playbooks."""

    _instance: PlaybookRegistry | None = None
    _lock: threading.Lock = threading.Lock()

    def __init__(self) -> None:
        self._playbooks: dict[str, Playbook] = {}

    @classmethod
    def instance(cls) -> PlaybookRegistry:
        if cls._instance is None:
            with cls._lock:
                # Double-checked locking
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    # ──────────────────────────────────────────────────────────
    # Registration
    # ──────────────────────────────────────────────────────────

    def register(self, playbook: Playbook) -> None:
        """Register a playbook. Raises ValueError on duplicate ID."""
        if playbook.id in self._playbooks:
            raise ValueError(f"Playbook '{playbook.id}' is already registered.")
        self._playbooks[playbook.id] = playbook

    def register_many(self, *playbooks: Playbook) -> None:
        for pb in playbooks:
            self.register(pb)

    # ──────────────────────────────────────────────────────────
    # Retrieval
    # ──────────────────────────────────────────────────────────

    def get(self, playbook_id: str) -> Playbook:
        """Return playbook by ID. Raises KeyError if not found."""
        try:
            return self._playbooks[playbook_id]
        except KeyError:
            available = ", ".join(self._playbooks.keys())
            raise KeyError(f"Playbook '{playbook_id}' not found. Available: {available}")

    def list_all(self) -> list[dict]:
        """Returns a summary list of all registered playbooks."""
        return [
            {
                "id": pb.id,
                "name": pb.name,
                "description": pb.description,
                "mitre_ids": pb.mitre_ids,
                "severity": pb.severity.value,
                "steps": len(pb.steps),
                "tags": pb.tags,
                "case_template": pb.case_template,
                "soar_workflow_id": pb.soar_workflow_id,
            }
            for pb in sorted(self._playbooks.values(), key=lambda p: p.id)
        ]

    def find_for_alert(
        self,
        rule_id: str = "",
        mitre_ids: list[str] | None = None,
    ) -> list[Playbook]:
        """
        Returns playbooks relevant to the given Wazuh rule_id or MITRE IDs.
        Sorted by severity (critical first).
        """
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        matches = [pb for pb in self._playbooks.values() if pb.matches(rule_id=rule_id, mitre_ids=mitre_ids or [])]
        return sorted(matches, key=lambda p: severity_order.get(p.severity.value, 9))

    def trigger(self, playbook_id: str, ctx: PlaybookContext) -> PlaybookResult:
        """Convenience method: get + render in one call."""
        pb = self.get(playbook_id)
        return pb.render(ctx)

    def __len__(self) -> int:
        return len(self._playbooks)

    def __repr__(self) -> str:
        ids = ", ".join(self._playbooks.keys())
        return f"<PlaybookRegistry [{len(self._playbooks)} playbooks]: {ids}>"
