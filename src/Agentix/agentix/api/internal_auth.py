"""
Internal API Key authentication for Gateway → Core communication.

This middleware ensures that only the trusted Gateway (or other internal
services that possess the shared secret) can call the Core API endpoints.

In development mode (no key configured), all requests are allowed with a
warning log.
"""
from __future__ import annotations

import structlog
from fastapi import HTTPException, Request, status
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from agentic_common.settings import settings

logger = structlog.get_logger(__name__)

_HEADER_NAME = "X-Internal-Api-Key"

# Paths that do NOT require internal auth (health checks, docs, etc.)
_EXEMPT_PATHS: frozenset[str] = frozenset({
    "/health",
    "/docs",
    "/openapi.json",
    "/redoc",
})


class InternalApiKeyMiddleware(BaseHTTPMiddleware):
    """Reject requests that lack a valid internal API key."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Skip auth for exempt paths and webhooks (which handle their own HMAC auth)
        if request.url.path in _EXEMPT_PATHS or request.url.path.startswith("/v1/webhooks"):
            return await call_next(request)

        expected_key = settings.agentix_internal_api_key

        # Strict enforcement: no key configured -> fail closed
        if not expected_key:
            logger.critical(
                "internal_auth.missing_configuration",
                msg="AGENTIX_INTERNAL_API_KEY is not set! Failing closed.",
                path=request.url.path,
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Server misconfiguration: Internal auth key is missing.",
            )

        provided_key = request.headers.get(_HEADER_NAME)

        if not provided_key or provided_key != expected_key:
            logger.warning(
                "internal_auth.rejected",
                path=request.url.path,
                reason="missing or invalid API key",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid or missing internal API key.",
            )

        return await call_next(request)
