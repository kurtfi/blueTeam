import asyncio

import structlog
from attack_simulator.api.routes import router, simulation_service
from attack_simulator.models import db_repo
from fastapi import FastAPI

from fastapi.staticfiles import StaticFiles
from pathlib import Path

logger = structlog.get_logger(__name__)

app = FastAPI(
    title="AttackSimulator REST API",
    description="Standalone REST API for simulating security alerts",
    version="1.0.0",
)

# Mount static files for Web UI
static_dir = Path(__file__).parent.parent / "static"
app.mount("/ui", StaticFiles(directory=str(static_dir), html=True), name="ui")

# Mount the routes
app.include_router(router, prefix="/v1")


@app.on_event("startup")
async def startup_event():
    logger.info("Starting up AttackSimulator REST API...")
    # Start the bulk run poller inside this standalone process
    app.state.bulk_poller_task = asyncio.create_task(simulation_service.bulk_run_status_poller())
    logger.info("Bulk run status poller task started in AttackSimulator.")


@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Shutting down AttackSimulator REST API...")
    # Cancel the bulk poller task
    bulk_poller_task = getattr(app.state, "bulk_poller_task", None)
    if bulk_poller_task and not bulk_poller_task.done():
        bulk_poller_task.cancel()
        try:
            await bulk_poller_task
        except asyncio.CancelledError:
            pass
    # Clean database connections
    await db_repo.close()
