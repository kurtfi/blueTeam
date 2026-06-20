"""
Abstract interface for alert dispatching infrastructure.
"""

from abc import ABC, abstractmethod
from typing import Any


class AlertSender(ABC):
    """
    Interface for sending security alerts to a SIEM/Webhook or mock receiver.
    """

    @abstractmethod
    async def send(self, alert_payload: dict[str, Any], technique_id: str) -> str | None:
        """
        Dispatches a single alert payload. Returns a session/tracking ID or None on failure.
        """
        pass
