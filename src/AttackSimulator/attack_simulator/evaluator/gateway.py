"""
Gateway interface and implementation for expected playbook resolution.
"""

from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class PlaybookRegistryGateway:
    """
    Decouples AttackSimulator from the concrete triage_core playbooks registry.
    """

    def __init__(self) -> None:
        self._registry: Any = None
        self._loaded = False

    def _load_registry(self) -> Any:
        if not self._loaded:
            try:
                from triage_core.playbooks import registry as pb_registry

                self._registry = pb_registry
            except Exception as e:
                logger.warning("gateway.playbook_registry_load_failed", error=str(e))
                self._registry = None
            self._loaded = True
        return self._registry

    def find_playbooks_for_mitre(self, mitre_ids: list[str]) -> list[Any]:
        """
        Queries triage_core playbook registry and returns a list of candidate playbooks.
        """
        if not mitre_ids:
            return []

        registry = self._load_registry()
        if not registry:
            return []

        try:
            return registry.find_for_alert(mitre_ids=mitre_ids)
        except Exception as e:
            logger.error("gateway.playbook_find_failed", mitre_ids=mitre_ids, error=str(e))
            return []
