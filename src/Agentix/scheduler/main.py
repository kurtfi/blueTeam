import asyncio
import os
import structlog
from datetime import datetime

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

# We can reuse the Agentix API client if needed manually, or just use httpx
import httpx

logger = structlog.get_logger(__name__)

AGENTIX_API_URL = os.getenv("AGENTIX_API_URL", "http://localhost:8000")

async def run_report_task():
    """
    An example scheduled task that runs every day.
    It can trigger a system-wide Agentix session to perform some analysis.
    """
    logger.info("scheduler.run_report_task.started", time=datetime.now().isoformat())
    
    # We trigger the core API directly since it's an internal trusted cron
    # Or, it could use the same Agentix internal packages directly
    # Using HTTP here to keep it loosely coupled.
    async with httpx.AsyncClient() as client:
        try:
            # 1. Create a system session
            session_resp = await client.post(
                f"{AGENTIX_API_URL}/v1/session", 
                json={"user_id": "system-scheduler"}
            )
            session_resp.raise_for_status()
            session_id = session_resp.json()["session_id"]
            
            # 2. Trigger the task
            payload = {
                "session_id": session_id,
                "message": "Generate daily system report.",
                "agent": "researcher" 
            }
            
            # Since chat/stream returns SSE, we can just consume it or ignore it depending on requirements.
            # Here we just iterate to trigger the work.
            async with client.stream("POST", f"{AGENTIX_API_URL}/v1/chat/stream", json=payload) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    pass # Or log it if you want to trace the job
            
            logger.info("scheduler.run_report_task.completed", session_id=session_id)
            
        except Exception as e:
            logger.error("scheduler.run_report_task.failed", error=str(e))

async def main():
    logger.info("Starting Agentix Scheduler Service...")
    scheduler = AsyncIOScheduler()
    
    # Example: Run every day at 08:00
    # scheduler.add_job(run_report_task, CronTrigger(hour=8, minute=0))
    
    # For testing, you could run it every minute
    # scheduler.add_job(run_report_task, CronTrigger(minute="*"))
    
    scheduler.start()
    
    try:
        # Keep the main thread alive
        while True:
            await asyncio.sleep(3600)
    except (KeyboardInterrupt, SystemExit):
        logger.info("Shutting down Agentix Scheduler Service...")

if __name__ == "__main__":
    asyncio.run(main())
