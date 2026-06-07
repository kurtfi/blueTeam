"""
Langfuse — LLM Observability & Tracing for Agentix.

Provides a singleton Langfuse client and context-aware tracing utilities.
"""

from __future__ import annotations

import asyncio
import functools
from collections.abc import Callable
from typing import Any, TypeVar

import structlog
from agentic_common.settings import settings
from langfuse import Langfuse

logger = structlog.get_logger(__name__)

# Type variable for the function return type
R = TypeVar("R")


class ObservabilityManager:
    """
    Singleton manager for Langfuse tracing.
    """

    _instance: ObservabilityManager | None = None
    _client: Langfuse | None = None

    def __new__(cls) -> ObservabilityManager:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            if settings.langfuse_enabled:
                if not settings.langfuse_public_key or not settings.langfuse_secret_key:
                    logger.warning("observability.langfuse.missing_keys", action="disabling")
                else:
                    cls._client = Langfuse(
                        public_key=settings.langfuse_public_key,
                        secret_key=settings.langfuse_secret_key,
                        host=settings.langfuse_host,
                    )
                    logger.info("observability.langfuse.initialised", host=settings.langfuse_host)
        return cls._instance

    @property
    def client(self) -> Langfuse | None:
        return self._client

    def trace(self, name: str, session_id: str | None = None, user_id: str | None = None, **kwargs: Any) -> Any:
        """
        Start a new trace.
        """
        if not self._client:
            return None

        return self._client.trace(name=name, session_id=session_id, user_id=user_id, metadata=kwargs)

    async def flush(self) -> None:
        """
        Ensure all traces are sent to the server in a non-blocking thread.
        """
        if self._client:
            await asyncio.to_thread(self._client.flush)


# Global singleton
obs = ObservabilityManager()


def trace_it(name: str | None = None) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Decorator to wrap a function call in a Langfuse span.
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            if not obs.client:
                return await func(*args, **kwargs)

            # For now, we'll assume the trace is pass-through or handled by the caller
            return await func(*args, **kwargs)

        return async_wrapper

    return decorator
