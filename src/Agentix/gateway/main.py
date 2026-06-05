import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from gateway.routers import sessions, telegram, web, webhooks
from gateway.security.auth import auth_store

logger = structlog.get_logger(__name__)

# CORS origins — comma-separated list via env var, with safe defaults.
_cors_origins = os.getenv(
    "GATEWAY_ALLOWED_ORIGINS",
    "http://localhost:3000,http://localhost:5173"
).split(",")

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info("gateway.startup", message="Starting Agentix API Gateway...")
    try:
        await auth_store.setup_db()
        logger.info(
            "gateway.startup",
            message="Auth database table initialized/verified."
        )
    except Exception as e:
        logger.error("gateway.startup.db_init_failed", error=str(e))
        
    yield
    
    logger.info("gateway.shutdown", message="Shutting down Agentix API Gateway...")
    try:
        await auth_store.close()
        logger.info("gateway.shutdown", message="Authentication database connection closed.")
    except Exception as e:
        logger.error("gateway.shutdown.db_close_failed", error=str(e))

app = FastAPI(
    title="Agentix API Gateway",
    description=(
        "Gateway mapping Web, Telegram, and other channels "
        "to the core Agentix Orchestrator."
    ),
    version="1.0.0",
    lifespan=lifespan
)

# CORS config — restricted to known frontend origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _cors_origins],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# Register routers
app.include_router(web.router)
app.include_router(sessions.router)
app.include_router(telegram.router)
app.include_router(webhooks.router)

# Mount static files for frontend Web UI
static_dir = Path(__file__).parent / "static"
app.mount("/ui", StaticFiles(directory=str(static_dir), html=True), name="ui")

@app.get("/")
async def root_redirect() -> RedirectResponse:
    """Redirect root path to the Web UI dashboard"""
    return RedirectResponse(url="/ui/index.html")

@app.get("/health", tags=["System"])
async def health_check() -> dict[str, str]:
    """Simple health check endpoint"""
    return {"status": "ok", "service": "Agentix Gateway"}
