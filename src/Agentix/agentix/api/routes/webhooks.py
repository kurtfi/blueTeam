import hmac
import hashlib
import os
import uuid
import structlog
from fastapi import APIRouter, Request, BackgroundTasks, HTTPException, Header, Depends

from agentix.core.triage_workflow import process_wazuh_alert

logger = structlog.get_logger(__name__)

async def verify_hmac_signature(request: Request, x_webhook_signature: str = Header(None)):
    secret = os.getenv("AGENTIX_WEBHOOK_SECRET")
    if not secret:
        logger.error("webhooks.auth.missing_secret")
        raise HTTPException(status_code=500, detail="Webhook secret not configured")
    if not x_webhook_signature:
        raise HTTPException(status_code=401, detail="Missing X-Webhook-Signature header")
        
    body = await request.body()
    expected_mac = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_mac, x_webhook_signature):
        logger.warning("webhooks.auth.invalid_signature")
        raise HTTPException(status_code=403, detail="Invalid webhook signature")

router = APIRouter(tags=["webhooks"])

@router.post("/v1/webhooks/shuffle/wazuh", dependencies=[Depends(verify_hmac_signature)])
async def handle_wazuh_alert(request: Request, background_tasks: BackgroundTasks):
    """
    Receives alerts from Wazuh via Shuffle.
    """
    try:
        payload = await request.json()
    except Exception as e:
        logger.error("webhooks.wazuh.invalid_json", error=str(e))
        return {"status": "error", "message": "Invalid JSON"}

    # Generate a unique session ID for the triage process
    session_id = f"triage-{uuid.uuid4()}"
    
    # Run the orchestrator in the background to avoid blocking the webhook response
    background_tasks.add_task(process_wazuh_alert, session_id, payload)
    
    logger.info("webhooks.wazuh.received", session_id=session_id)
    return {
        "status": "received", 
        "session_id": session_id, 
        "message": "Triage workflow initiated"
    }
