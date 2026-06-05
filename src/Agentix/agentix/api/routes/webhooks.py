import hashlib
import hmac
import os
import uuid
from datetime import datetime

import structlog
from agentic_common.memory import postgres_session_repo
from agentix.core.alert_dedup import AlertDeduplicator
from agentix.core.triage_workflow import process_siem_alert
from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Request

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

    # Generate a unique session ID for the triage process (strictly UUID format)
    session_uuid = uuid.uuid4()
    session_id = str(session_uuid)
    
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

    # Extract Wazuh alert metadata
    rule_id = (payload.get("rule", {}).get("id") 
               or payload.get("rule_id") 
               or payload.get("all_fields", {}).get("rule", {}).get("id"))
    rule_desc = (payload.get("rule", {}).get("description") 
                 or payload.get("rule_description") 
                 or "Unknown SIEM Alert")
    severity_val = (payload.get("rule", {}).get("level") 
                     or payload.get("level"))
    try:
        severity = int(severity_val) if severity_val is not None else None
    except ValueError:
        severity = None
        
    src_ip = (payload.get("data", {}).get("srcip") 
              or payload.get("srcip"))
    mitre_ids = (payload.get("rule", {}).get("mitre", {}).get("id") 
                 or payload.get("mitre_ids"))
    if mitre_ids and isinstance(mitre_ids, str):
        mitre_ids = [mitre_ids]

    # Display name format: rule_description + src_ip + timestamp
    timestamp_str = datetime.now().strftime("%b %d %H:%M")
    if src_ip:
        display_name = f"{rule_desc} from {src_ip} — {timestamp_str}"
    else:
        display_name = f"{rule_desc} — {timestamp_str}"

    # Create persistent session in PostgreSQL
    try:
        await postgres_session_repo.create_session(
            session_id=session_id,
            display_name=display_name,
            source="WAZUH",
            owner_id="wazuh",
            agent_name="soc_analyst",
            wazuh_rule_id=str(rule_id) if rule_id else None,
            wazuh_rule_desc=rule_desc,
            wazuh_severity=severity,
            source_ip=src_ip,
            mitre_ids=mitre_ids,
            alert_payload=payload,
        )
        # Log initial system event
        await postgres_session_repo.add_event(
            session_id=session_id,
            event_type="system",
            actor="wazuh",
            content=f"Triage workflow initiated for alert: {rule_desc}",
        )
    except Exception as e:
        logger.error("webhooks.postgres_creation_failed", session_id=session_id, error=str(e))
        # Proceed with background triage even if DB fails, or we can reject.
        # It's better to log and proceed in async webhook to avoid losing alerts.

    # Run the orchestrator in the background to avoid blocking the webhook response
    background_tasks.add_task(process_siem_alert, session_id, payload)
    
    logger.info("webhooks.siem.received", session_id=session_id)
    return {
        "status": "received", 
        "session_id": session_id, 
        "message": "Triage workflow initiated"
    }
