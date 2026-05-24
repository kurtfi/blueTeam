import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from gateway.routers import web, telegram
import gateway.security.firebase_auth  # Ensure firebase init runs

import os

logger = structlog.get_logger(__name__)

# CORS origins — comma-separated list via env var, with safe defaults.
_cors_origins = os.getenv(
    "GATEWAY_ALLOWED_ORIGINS",
    "http://localhost:3000,http://localhost:5173"
).split(",")

app = FastAPI(
    title="Agentix API Gateway",
    description="Gateway mapping Web, Telegram, and other channels to the core Agentix Orchestrator.",
    version="1.0.0"
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

@app.on_event("startup")
async def startup_event():
    logger.info("gateway.startup", message="Starting Agentix API Gateway...")

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("gateway.shutdown", message="Shutting down Agentix API Gateway...")

@app.get("/health", tags=["System"])
async def health_check():
    """Simple health check endpoint"""
    return {"status": "ok", "service": "Agentix Gateway"}
