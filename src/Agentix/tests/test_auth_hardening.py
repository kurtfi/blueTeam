import hmac
import hashlib
import pytest
from fastapi import Request, HTTPException
from unittest.mock import AsyncMock
from agentix.api.routes.webhooks import verify_hmac_signature


def mock_request(headers=None, body=b""):
    scope = {
        "type": "http",
        "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
    }
    req = Request(scope)
    req._receive = AsyncMock(return_value={"type": "http.request", "body": body, "more_body": False})
    return req


@pytest.mark.asyncio
async def test_webhook_fail_closed_missing_secret(monkeypatch):
    # Ensure environment variables are clear
    monkeypatch.delenv("AGENTIX_WEBHOOK_SECRET", raising=False)
    monkeypatch.delenv("AGENTIX_ALLOW_UNAUTHENTICATED_WEBHOOKS", raising=False)
    monkeypatch.delenv("AGENTIX_INTERNAL_API_KEY", raising=False)

    req = mock_request()
    with pytest.raises(HTTPException) as exc_info:
        await verify_hmac_signature(req)
    assert exc_info.value.status_code == 500
    assert "Webhook secret is not set" in exc_info.value.detail


@pytest.mark.asyncio
async def test_webhook_bypass_in_dev_mode(monkeypatch):
    monkeypatch.delenv("AGENTIX_WEBHOOK_SECRET", raising=False)
    monkeypatch.setenv("AGENTIX_ALLOW_UNAUTHENTICATED_WEBHOOKS", "True")
    monkeypatch.delenv("AGENTIX_INTERNAL_API_KEY", raising=False)

    req = mock_request()
    # Should not raise exception
    await verify_hmac_signature(req)


@pytest.mark.asyncio
async def test_webhook_internal_key_bypass(monkeypatch):
    monkeypatch.delenv("AGENTIX_WEBHOOK_SECRET", raising=False)
    monkeypatch.setenv("AGENTIX_INTERNAL_API_KEY", "super-secret-internal-key")

    req = mock_request(headers={"X-Internal-API-Key": "super-secret-internal-key"})
    # Should bypass validation and succeed
    await verify_hmac_signature(req, x_internal_api_key="super-secret-internal-key")


@pytest.mark.asyncio
async def test_webhook_signature_verification(monkeypatch):
    monkeypatch.setenv("AGENTIX_WEBHOOK_SECRET", "webhook-signing-key")
    monkeypatch.delenv("AGENTIX_INTERNAL_API_KEY", raising=False)

    body = b'{"alert": "test"}'
    valid_sig = hmac.new(b"webhook-signing-key", body, hashlib.sha256).hexdigest()

    # 1. Missing signature
    req = mock_request(body=body)
    with pytest.raises(HTTPException) as exc_info:
        await verify_hmac_signature(req)
    assert exc_info.value.status_code == 401

    # 2. Invalid signature
    req = mock_request(headers={"X-Webhook-Signature": "invalid-signature"}, body=body)
    with pytest.raises(HTTPException) as exc_info:
        await verify_hmac_signature(req, x_webhook_signature="invalid-signature")
    assert exc_info.value.status_code == 403

    # 3. Valid signature
    req = mock_request(headers={"X-Webhook-Signature": valid_sig}, body=body)
    await verify_hmac_signature(req, x_webhook_signature=valid_sig)
