"""
Sliding-window event aggregation logic for N:1 correlation rules.
"""

from datetime import datetime
from typing import Any


class EventAggregator:
    """
    Tracks and aggregates event occurrences based on group keys and sliding time windows.
    """

    def __init__(
        self, 
        group_by_fields: list[str], 
        threshold: int, 
        timeframe_seconds: int
    ) -> None:
        self.group_by_fields = group_by_fields
        self.threshold = threshold
        self.timeframe_seconds = timeframe_seconds
        # key: tuple(field_values) -> list of datetime timestamps
        self.state: dict[tuple[str, ...], list[datetime]] = {}

    def _get_group_key(self, event: dict[str, Any]) -> tuple[str, ...]:
        keys = []
        for field in self.group_by_fields:
            # Check common casings (e.g. IpAddress, IPAddress, srcip)
            val = None
            if field == "IpAddress":
                val = event.get("IpAddress") or event.get("IPAddress") or event.get("srcip")
            elif field == "User":
                val = event.get("User") or event.get("TargetUserName") or event.get("dstuser")
            
            if val is None:
                val = event.get(field)
                
            keys.append(str(val) if val is not None else "")
        return tuple(keys)

    def add_and_check(self, event: dict[str, Any], event_time: datetime) -> bool:
        """
        Adds a matched event to the group window and checks if aggregation threshold is met.
        Returns True if threshold is met, False otherwise.
        """
        key = self._get_group_key(event)
        if key not in self.state:
            self.state[key] = []

        # Add event timestamp
        self.state[key].append(event_time)

        # Slide time window: discard events older than timeframe
        self.state[key] = [
            t for t in self.state[key] 
            if (event_time - t).total_seconds() <= self.timeframe_seconds
        ]

        # Trigger if threshold met
        if len(self.state[key]) >= self.threshold:
            # Flush state for this key to prevent double triggers on the very next event
            self.state[key] = []
            return True

        return False
