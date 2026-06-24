import hashlib
import hmac
import os
import uuid
from datetime import datetime

import structlog
from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Request

from agentic_common.memory import postgres_session_repo
from agentix.core.alert_dedup import AlertDeduplicator
from agentix.core.triage_workflow import process_siem_alert

logger = structlog.get_logger(__name__)


async def get_deduplicator(request: Request) -> AlertDeduplicator:
    return request.app.state.deduplicator


async def verify_hmac_signature(
    request: Request, x_webhook_signature: str = Header(None), x_internal_api_key: str = Header(None)
):
    from fastapi.params import Header as FastAPIHeader
    if isinstance(x_webhook_signature, FastAPIHeader):
        x_webhook_signature = None
    if isinstance(x_internal_api_key, FastAPIHeader):
        x_internal_api_key = None

    import secrets

    # 1. Allow bypass if internal API key matches (e.g. from internal scripts)
    internal_key = os.getenv("AGENTIX_INTERNAL_API_KEY")
    if internal_key and x_internal_api_key and secrets.compare_digest(x_internal_api_key, internal_key):
        logger.info("webhooks.auth.internal_key_authorized")
        return

    # 2. Check if webhook secret is configured (Fail-Closed by default)
    secret = os.getenv("AGENTIX_WEBHOOK_SECRET")
    if not secret:
        allow_unauth = os.getenv("AGENTIX_ALLOW_UNAUTHENTICATED_WEBHOOKS", "False").lower() == "true"
        if allow_unauth:
            logger.warning(
                "webhooks.auth.missing_secret_bypass",
                msg="Webhook secret is missing! Bypassing signature verification (INSECURE DEV MODE)."
            )
            return
        else:
            logger.critical(
                "webhooks.auth.missing_secret_fail_closed",
                msg="AGENTIX_WEBHOOK_SECRET is not configured! Failing closed. Set AGENTIX_ALLOW_UNAUTHENTICATED_WEBHOOKS=True to override for local development."
            )
            raise HTTPException(
                status_code=500,
                detail="Webhook configuration error: Webhook secret is not set."
            )

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
async def handle_siem_alert(
    request: Request, background_tasks: BackgroundTasks, dedup: AlertDeduplicator = Depends(get_deduplicator)
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
        rule_id = (
            payload.get("rule_id")
            or payload.get("rule", {}).get("id")
            or payload.get("all_fields", {}).get("rule", {}).get("id")
        )
        logger.info("webhooks.siem.deduplicated", existing_session=existing_session, rule_id=rule_id)
        return {
            "status": "deduplicated",
            "existing_session": existing_session,
            "message": "Alert already being triaged",
        }

    # Extract Wazuh alert metadata
    rule_id = (
        payload.get("rule_id")
        or payload.get("rule", {}).get("id")
        or payload.get("all_fields", {}).get("rule", {}).get("id")
    )
    if rule_id:
        rule_id = str(rule_id)[:255]

    rule_desc = (
        payload.get("title")
        or payload.get("rule_description")
        or payload.get("rule", {}).get("description")
        or payload.get("all_fields", {}).get("rule", {}).get("description")
        or "Unknown SIEM Alert"
    )
    rule_desc = str(rule_desc)[:1000]

    severity_val = (
        payload.get("severity")
        or payload.get("rule", {}).get("level")
        or payload.get("all_fields", {}).get("rule", {}).get("level")
        or payload.get("level")
    )
    try:
        severity = int(severity_val) if severity_val is not None else None
    except ValueError:
        severity = None

    src_ip = (
        payload.get("srcip")
        or payload.get("data", {}).get("srcip")
        or payload.get("all_fields", {}).get("data", {}).get("srcip")
        or payload.get("all_fields", {}).get("syslog_headers", {}).get("from")
    )
    if src_ip:
        src_ip = str(src_ip)[:255]

    mitre_ids = (
        payload.get("mitre_ids")
        or payload.get("rule", {}).get("mitre", {}).get("id")
        or payload.get("all_fields", {}).get("rule", {}).get("mitre", {}).get("id")
    )
    if mitre_ids and isinstance(mitre_ids, str):
        mitre_ids = [mitre_ids]

    # Display name format: [MITRE_ID] rule_description from src_ip — timestamp
    timestamp_str = datetime.now().strftime("%b %d %H:%M")
    mitre_str = ", ".join(mitre_ids) if mitre_ids else ""
    prefix = f"[{mitre_str}] " if mitre_str else ""

    if src_ip:
        display_name = f"{prefix}{rule_desc} from {src_ip} — {timestamp_str}"
    else:
        display_name = f"{prefix}{rule_desc} — {timestamp_str}"
    display_name = display_name[:255]

    # Create persistent session in PostgreSQL
    try:
        await postgres_session_repo.create_session(
            session_id=session_id,
            display_name=display_name,
            source="SIEM",
            owner_id="siem",
            agent_name="soc_analyst",
            siem_rule_id=rule_id,
            siem_rule_desc=rule_desc,
            siem_severity=severity,
            source_ip=src_ip,
            mitre_ids=mitre_ids,
            alert_payload=payload,
        )
        # Log initial system event
        await postgres_session_repo.add_event(
            session_id=session_id,
            event_type="system",
            actor="siem",
            content=f"Triage workflow initiated for alert: {rule_desc}"[:1000],
        )
    except Exception as e:
        logger.critical(
            "webhooks.postgres_creation_failed", session_id=session_id, error=str(e), alert=True, db_failure=True
        )
        # Proceed with background triage even if DB fails, or we can reject.
        # It's better to log and proceed in async webhook to avoid losing alerts.

    # Run the orchestrator in the background to avoid blocking the webhook response
    background_tasks.add_task(process_siem_alert, session_id, payload)

    logger.info("webhooks.siem.received", session_id=session_id)
    return {"status": "received", "session_id": session_id, "message": "Triage workflow initiated"}


@router.post("/v1/webhooks/simulation", dependencies=[Depends(verify_hmac_signature)])
async def handle_simulation_alert(
    request: Request, background_tasks: BackgroundTasks, dedup: AlertDeduplicator = Depends(get_deduplicator)
):
    """
    Receives alerts from simulation integration directly.
    """
    try:
        payload = await request.json()
    except Exception as e:
        logger.error("webhooks.simulation.invalid_json", error=str(e))
        return {"status": "error", "message": "Invalid JSON"}

    # Generate a unique session ID for the triage process (strictly UUID format)
    session_uuid = uuid.uuid4()
    session_id = str(session_uuid)

    # Check for duplication in Redis
    is_dup, existing_session = await dedup.check_and_register(payload, session_id)
    if is_dup:
        rule_id = (
            payload.get("rule_id")
            or payload.get("rule", {}).get("id")
            or payload.get("all_fields", {}).get("rule", {}).get("id")
        )
        logger.info("webhooks.simulation.deduplicated", existing_session=existing_session, rule_id=rule_id)
        return {
            "status": "deduplicated",
            "existing_session": existing_session,
            "message": "Alert already being triaged",
        }

    # Extract Wazuh alert metadata
    rule_id = (
        payload.get("rule_id")
        or payload.get("rule", {}).get("id")
        or payload.get("all_fields", {}).get("rule", {}).get("id")
    )
    if rule_id:
        rule_id = str(rule_id)[:255]

    rule_desc = (
        payload.get("title")
        or payload.get("rule_description")
        or payload.get("rule", {}).get("description")
        or payload.get("all_fields", {}).get("rule", {}).get("description")
        or "Unknown SIEM Alert"
    )
    rule_desc = str(rule_desc)[:1000]

    severity_val = (
        payload.get("severity")
        or payload.get("rule", {}).get("level")
        or payload.get("all_fields", {}).get("rule", {}).get("level")
        or payload.get("level")
    )
    try:
        severity = int(severity_val) if severity_val is not None else None
    except ValueError:
        severity = None

    src_ip = (
        payload.get("srcip")
        or payload.get("data", {}).get("srcip")
        or payload.get("all_fields", {}).get("data", {}).get("srcip")
        or payload.get("all_fields", {}).get("syslog_headers", {}).get("from")
    )
    if src_ip:
        src_ip = str(src_ip)[:255]

    mitre_ids = (
        payload.get("mitre_ids")
        or payload.get("rule", {}).get("mitre", {}).get("id")
        or payload.get("all_fields", {}).get("rule", {}).get("mitre", {}).get("id")
    )
    if mitre_ids and isinstance(mitre_ids, str):
        mitre_ids = [mitre_ids]

    # Display name format: [MITRE_ID] rule_description from src_ip — timestamp
    timestamp_str = datetime.now().strftime("%b %d %H:%M")
    mitre_str = ", ".join(mitre_ids) if mitre_ids else ""
    prefix = f"[{mitre_str}] " if mitre_str else ""

    if src_ip:
        display_name = f"{prefix}{rule_desc} from {src_ip} — {timestamp_str}"
    else:
        display_name = f"{prefix}{rule_desc} — {timestamp_str}"
    display_name = display_name[:255]

    # Create persistent session in PostgreSQL
    try:
        await postgres_session_repo.create_session(
            session_id=session_id,
            display_name=display_name,
            source="SIEM",
            owner_id="siem",
            agent_name="simulation_analyst",
            siem_rule_id=rule_id,
            siem_rule_desc=rule_desc,
            siem_severity=severity,
            source_ip=src_ip,
            mitre_ids=mitre_ids,
            alert_payload=payload,
        )
        # Log initial system event
        await postgres_session_repo.add_event(
            session_id=session_id,
            event_type="system",
            actor="siem",
            content=f"Simulation triage workflow initiated for alert: {rule_desc}"[:1000],
        )
    except Exception as e:
        logger.critical(
            "webhooks.postgres_creation_failed", session_id=session_id, error=str(e), alert=True, db_failure=True
        )

    # Run the orchestrator in the background to avoid blocking the webhook response
    background_tasks.add_task(process_siem_alert, session_id, payload, "simulation_analyst")

    logger.info("webhooks.simulation.received", session_id=session_id)
    return {"status": "received", "session_id": session_id, "message": "Simulation triage workflow initiated"}
