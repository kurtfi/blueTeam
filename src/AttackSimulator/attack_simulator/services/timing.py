"""
Timing strategy engine to control pacing of event replays.
"""

import asyncio
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class TimingStrategy(ABC):
    """
    Abstract interface for log replay timing pacing.
    """

    @abstractmethod
    async def wait_before_next(self, current_event: dict[str, Any], next_event: dict[str, Any]) -> None:
        """
        Determines how long to sleep before replaying the next event.
        """
        pass


class ConstantDelayStrategy(TimingStrategy):
    """
    Paces replays using a fixed constant delay (in seconds) between each event.
    """

    def __init__(self, delay_seconds: float = 1.0) -> None:
        self.delay_seconds = max(0.0, delay_seconds)

    async def wait_before_next(self, current_event: dict[str, Any], next_event: dict[str, Any]) -> None:
        if self.delay_seconds > 0:
            logger.debug("timing.constant_sleep", sleep_seconds=self.delay_seconds)
            await asyncio.sleep(self.delay_seconds)


class OriginalDeltaStrategy(TimingStrategy):
    """
    Paces replays by computing the time difference between consecutive events' original timestamps.
    """

    def __init__(self, default_delay: float = 1.0, max_delay: float = 30.0) -> None:
        self.default_delay = max(0.0, default_delay)
        self.max_delay = max(0.0, max_delay)

    def _parse_timestamp(self, event: dict[str, Any]) -> datetime | None:
        """Helper to extract and parse ISO timestamp from wazuh_alert dict."""
        try:
            alert = event.get("wazuh_alert") if "wazuh_alert" in event else event
            if not isinstance(alert, dict):
                return None
            ts_str = alert.get("@timestamp")
            if not ts_str:
                return None
            # Standardize 'Z' to '+00:00' to be compatible with datetime.fromisoformat
            if ts_str.endswith("Z"):
                ts_str = ts_str[:-1] + "+00:00"
            return datetime.fromisoformat(ts_str)
        except Exception:
            return None

    async def wait_before_next(self, current_event: dict[str, Any], next_event: dict[str, Any]) -> None:
        t1 = self._parse_timestamp(current_event)
        t2 = self._parse_timestamp(next_event)

        if not t1 or not t2:
            logger.warning("timing.timestamp_missing", fallback_delay=self.default_delay)
            await asyncio.sleep(self.default_delay)
            return

        delta = (t2 - t1).total_seconds()

        # Sanity check: if timestamps are out of order or equal, fallback to default delay
        if delta <= 0:
            sleep_time = self.default_delay
        else:
            # Apply the user-approved cap
            sleep_time = min(delta, self.max_delay)

        logger.debug(
            "timing.delta_sleep",
            original_delta=delta,
            applied_sleep=sleep_time,
            cap=self.max_delay,
        )

        if sleep_time > 0:
            await asyncio.sleep(sleep_time)


def get_timing_strategy(mode: str, base_delay: float = 1.0, max_delay: float = 30.0) -> TimingStrategy:
    """
    Factory function to resolve the timing strategy.
    """
    m = mode.lower().strip()
    if m == "original":
        return OriginalDeltaStrategy(default_delay=base_delay, max_delay=max_delay)
    else:
        return ConstantDelayStrategy(delay_seconds=base_delay)
