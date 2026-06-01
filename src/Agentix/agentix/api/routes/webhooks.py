import hmac
import hashlib
import os
import uuid
import structlog
from fastapi import APIRouter, Request, BackgroundTasks, HTTPException, Header, Depends

from agentix.core.triage_workflow import process_siem_alert

from agentix.core.alert_dedup import AlertDeduplicator

logger = structlog.get_logger(__name__)

async def get_deduplicator(request: Request) -> AlertDeduplicator:
    return request.app.state.deduplicator

async def verify_hmac_signature(
    request: Request,
    x_webhook_signature: str = Header(None),
    x_internal_api_key: str = Header(None)
):
    # 1. Allow bypass if internal API key matches (e.g. from internal scripts)
    internal_key = os.getenv("AGENTIX_INTERNAL_API_KEY")
    if internal_key and x_internal_api_key == internal_key:
        logger.info("webhooks.auth.internal_key_authorized")
        return

    # 2. Check if webhook secret is configured
    secret = os.getenv("AGENTIX_WEBHOOK_SECRET")
    if not secret:
        logger.warning("webhooks.auth.missing_secret_bypass")
        return
        
    # 3. Fall back to standard signature verification
    if not x_webhook_signature:
        raise HTTPException(status_code=401, detail="Missing X-Webhook-Signature header")
        
    body = await request.body()
    expected_mac = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_mac, x_webhook_signature):
        logger.warning("webhooks.auth.invalid_signature")
        raise HTTPException(status_code=403, detail="Invalid webhook signature")

router = APIRouter(tags=["webhooks"])

@router.post("/v1/webhooks/siem", dependencies=[Depends(verify_hmac_signature)])
@router.post("/v1/webhooks/wazuh", dependencies=[Depends(verify_hmac_signature)])
async def handle_siem_alert(
    request: Request,
    background_tasks: BackgroundTasks,
    dedup: AlertDeduplicator = Depends(get_deduplicator)
):
    """
    Receives alerts from SIEM integration directly.
    """
    try:
        payload = await request.json()
    except Exception as e:
        logger.error("webhooks.siem.invalid_json", error=str(e))
        return {"status": "error", "message": "Invalid JSON"}

    # Generate a unique session ID for the triage process
    session_id = f"triage-{uuid.uuid4()}"
    
    # Check for duplication in Redis
    is_dup, existing_session = await dedup.check_and_register(payload, session_id)
    if is_dup:
        rule_id = (payload.get("rule_id") 
                   or payload.get("rule", {}).get("id") 
                   or payload.get("all_fields", {}).get("rule", {}).get("id"))
        logger.info(
            "webhooks.siem.deduplicated",
            existing_session=existing_session,
            rule_id=rule_id
        )
        return {
            "status": "deduplicated",
            "existing_session": existing_session,
            "message": "Alert already being triaged"
        }

    # Run the orchestrator in the background to avoid blocking the webhook response
    background_tasks.add_task(process_siem_alert, session_id, payload)
    
    logger.info("webhooks.siem.received", session_id=session_id)
    return {
        "status": "received", 
        "session_id": session_id, 
        "message": "Triage workflow initiated"
    }
