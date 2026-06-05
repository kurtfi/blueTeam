import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

# Add src/Agentix and src/AgenticCommon to sys.path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir))
sys.path.insert(0, str(root_dir.parent / "AgenticCommon"))

# Mock auth_store.setup_db during module load before importing app to avoid database connection
with patch("gateway.security.auth.auth_store.setup_db", new_callable=AsyncMock) as mock_setup:
    from gateway.main import app

client = TestClient(app)

@pytest.mark.asyncio
@patch("gateway.routers.webhooks.httpx.AsyncClient")
async def test_webhook_forwarding_success(mock_async_client):
    # Mock Response
    mock_response = httpx.Response(
        status_code=202,
        content=b'{"status": "received", "session_id": "triage-123"}',
        headers={"content-type": "application/json"}
    )
    
    # Mock AsyncClient post method
    mock_client_instance = AsyncMock()
    mock_client_instance.post.return_value = mock_response
    
    # Setup context manager return value
    mock_async_client.return_value.__aenter__.return_value = mock_client_instance
    
    # Test request
    payload = {"alert_id": "999", "rule": {"level": 10}}
    headers = {
        "Content-Type": "application/json",
        "X-Webhook-Signature": "mock-hmac-signature-value"
    }
    
    response = client.post(
        "/v1/webhooks/wazuh",
        json=payload,
        headers=headers
    )
    
    # Assert status code and response payload match the downstream mocked api response
    assert response.status_code == 202
    assert response.json() == {"status": "received", "session_id": "triage-123"}
    
    # Verify post was called with correct target URL, headers and body
    mock_client_instance.post.assert_called_once()
    call_args = mock_client_instance.post.call_args
    assert call_args is not None
    assert "/v1/webhooks/wazuh" in call_args[0][0]
    assert call_args[1]["headers"]["x-webhook-signature"] == "mock-hmac-signature-value"
    assert b'"alert_id":"999"' in call_args[1]["content"]

@pytest.mark.asyncio
@patch("gateway.routers.webhooks.httpx.AsyncClient")
async def test_webhook_forwarding_failure(mock_async_client):
    # Mock AsyncClient post method to raise an HTTPError
    mock_client_instance = AsyncMock()
    mock_client_instance.post.side_effect = httpx.HTTPError("Connection failed")
    mock_async_client.return_value.__aenter__.return_value = mock_client_instance
    
    response = client.post(
        "/v1/webhooks/wazuh",
        json={"test": "data"},
        headers={"X-Webhook-Signature": "signature"}
    )
    
    # Gateway should return 502 Bad Gateway
    assert response.status_code == 502
    assert response.json()["detail"] == "Error forwarding request to agentix-api"
