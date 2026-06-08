"""
Redis-backed alert deduplication with time-window throttling.

Storage: Redis — persistent and distributed across worker instances.
- Uses settings.redis_url connection string
- Race-condition free atomic check-and-set
"""

from __future__ import annotations

import redis.asyncio as redis
import structlog

from agentic_common.settings import settings

logger = structlog.get_logger(__name__)


class AlertKeyExtractor:
    """
    Extracts deduplication keys from SIEM alert payloads.
    Separates the payload schema logic from the Redis deduplication workflow (SRP).
    """

    @staticmethod
    def extract_rule_id(payload: dict) -> str:
        """Finds rule.id in the alert payload."""
        all_fields = payload.get("all_fields", {})
        rule_id = (
            payload.get("rule_id") or payload.get("rule", {}).get("id") or all_fields.get("rule", {}).get("id") or ""
        )
        return str(rule_id).strip()

    @staticmethod
    def extract_src_ip(payload: dict) -> str:
        """Finds source IP in the alert payload."""
        all_fields = payload.get("all_fields", {})
        src_ip = (
            payload.get("srcip")
            or payload.get("data", {}).get("srcip")
            or all_fields.get("data", {}).get("srcip")
            or all_fields.get("agent", {}).get("ip")
            or payload.get("agent", {}).get("ip")
            or ""
        )
        return str(src_ip).strip()

    @classmethod
    def extract_key(cls, payload: dict) -> str | None:
        """
        Derives the deduplication key string.
        Format: "rule_id:src_ip"
        """
        rule_id = cls.extract_rule_id(payload)
        if not rule_id:
            return None
        src_ip = cls.extract_src_ip(payload)
        return f"{rule_id}:{src_ip or 'unknown'}"


class AlertDeduplicator:
    def __init__(self, redis_url: str = settings.redis_url, window_seconds: int = 120):
        self._redis = redis.from_url(redis_url, decode_responses=True)
        self._window = window_seconds
        # Rule IDs that should never be deduplicated (one-shot events)
        self._bypass_rules: set[str] = set()

    def _extract_key(self, payload: dict) -> str | None:
        """Deprecated: Use AlertKeyExtractor.extract_key directly. Maintained for backwards compatibility."""
        return AlertKeyExtractor.extract_key(payload)

    async def check_and_register(self, payload: dict, session_id: str) -> tuple[bool, str | None]:
        """
        Check if the alert has already been received within the time window.
        Returns (is_duplicate, existing_session_id).
        """
        rule_id = AlertKeyExtractor.extract_rule_id(payload)

        logger.debug("alert_dedup.checking", rule_id=rule_id, session_id=session_id)
        if rule_id in self._bypass_rules:
            logger.debug("alert_dedup.bypass_rule", rule_id=rule_id)
            return False, None

        key = AlertKeyExtractor.extract_key(payload)
        if not key:
            logger.debug("alert_dedup.no_key", payload=payload)
            return False, None

        redis_key = f"dedup:alert:{key}"
        logger.debug("alert_dedup.redis_key", redis_key=redis_key)

        # Atomically check-and-set if not exists with a TTL
        success = await self._redis.set(redis_key, session_id, nx=True, ex=self._window)
        logger.debug("alert_dedup.set_nx_result", success=success)
        if success:
            # Successfully set -> this is the first alert in the window (not a duplicate)
            return False, None

        # Key already exists -> this is a duplicate alert
        existing_sid = await self._redis.get(redis_key)
        logger.debug("alert_dedup.duplicate_found", existing_sid=existing_sid)
        if existing_sid:
            return True, existing_sid

        # Fallback if key expired between set and get
        await self._redis.set(redis_key, session_id, ex=self._window)
        return False, None

    async def aclose(self):
        """Close the Redis client connection pool."""
        await self._redis.aclose()
