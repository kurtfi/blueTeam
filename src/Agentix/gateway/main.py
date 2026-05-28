import structlog
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from gateway.routers import web, telegram, webhooks
from gateway.security.auth import auth_store

import os

logger = structlog.get_logger(__name__)

# CORS origins — comma-separated list via env var, with safe defaults.
_cors_origins = os.getenv(
    "GATEWAY_ALLOWED_ORIGINS",
    "http://localhost:3000,http://localhost:5173"
).split(",")

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("gateway.startup", message="Starting Agentix API Gateway...")
    try:
        await auth_store.setup_db()
        logger.info("gateway.startup", message="Authentication database table initialized/verified.")
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
    description="Gateway mapping Web, Telegram, and other channels to the core Agentix Orchestrator.",
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
app.include_router(telegram.router)
app.include_router(webhooks.router)

@app.get("/health", tags=["System"])
async def health_check():
    """Simple health check endpoint"""
    return {"status": "ok", "service": "Agentix Gateway"}
