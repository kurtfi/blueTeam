import os

# import httpx for sending messages back to telegram
import httpx
import structlog
from fastapi import APIRouter, BackgroundTasks, HTTPException, Request

from gateway.services.agentix_client import ask_agentix_aggregated

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/telegram", tags=["Telegram Webhook"])

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")


# Pseudo-Database for Telegram ID -> Firebase UID mapping
# In a real scenario, this would be a Postgres/Redis/Firestore call
async def get_firebase_uid_from_telegram(telegram_id: int) -> str | None:
    """
    Looks up the Telegram ID in the database and returns the mapped Firebase UID.
    Returns None if the account is not linked.
    """
    # TODO: Implement real database lookup
    # For now, if the env variable allows a bypass, we just return a dummy
    # or return None to trigger the linking flow.
    logger.debug("gateway.telegram.lookup_uid", telegram_id=telegram_id)
    return "dummy-firebase-uid"


def send_telegram_message(chat_id: int, text: str):
    """
    Sends a message back to the Telegram chat.
    """
    if not TELEGRAM_BOT_TOKEN:
        logger.warning("TELEGRAM_BOT_TOKEN is not set.")
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": chat_id, "text": text}
    try:
        httpx.post(url, json=payload, timeout=10.0)
    except Exception as e:
        logger.error("gateway.telegram.send_message_failed", error=str(e))


async def handle_telegram_update(update: dict):
    if "message" not in update:
        return

    message = update["message"]
    chat_id = message.get("chat", {}).get("id")
    text = message.get("text", "")
    telegram_id = message.get("from", {}).get("id")

    if not text or not telegram_id:
        return

    # 1. Identity Resolution (Telegram ID -> Firebase UID)
    firebase_uid = await get_firebase_uid_from_telegram(telegram_id)

    if not firebase_uid:
        # User is not linked. Send the linking URL.
        link_url = f"https://yourapp.com/link-telegram?tid={telegram_id}"
        send_telegram_message(
            chat_id,
            f"Your account is not linked to the system. Please link your account at the following address:\n{link_url}",
        )
        return

    # User is valid, we can process the message.
    # Send intermediate "thinking" message optional.

    # 2. Ask Agentix and Aggregate Response
    # Since this is a background task, we can afford to wait.
    try:
        response_text = await ask_agentix_aggregated(user_id=firebase_uid, message=text)
        if not response_text:
            response_text = "Your request was processed but no response could be generated."

        send_telegram_message(chat_id, response_text)
    except Exception as e:
        logger.error("gateway.telegram.processing_failed", error=str(e))
        send_telegram_message(chat_id, "I cannot process your request at this time.")


@router.post("/webhook", summary="Receive Telegram Webhook updates")
async def telegram_webhook(request: Request, background_tasks: BackgroundTasks):
    """
    Endpoint for the Telegram Webhook.
    It returns 200 OK immediately and handles the heavy lifting in a background task.
    """
    try:
        update = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    # Queue the message processing in the background immediately so Telegram doesn't timeout
    background_tasks.add_task(handle_telegram_update, update)

    return {"status": "ok"}
