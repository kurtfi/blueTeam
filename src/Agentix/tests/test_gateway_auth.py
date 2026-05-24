import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
import sys
from pathlib import Path

# Add src/Agentix to sys.path
root_dir = Path(__file__).resolve().parent.parent
sys.path.append(str(root_dir))

from gateway.main import app
from gateway.security.firebase_auth import verify_firebase_token

client = TestClient(app)

@pytest.fixture
def mock_firebase_auth():
    with patch("gateway.security.firebase_auth.auth.verify_id_token") as mock:
        yield mock

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "Agentix Gateway"}

def test_me_endpoint_unauthorized():
    response = client.get("/web/me")
    assert response.status_code == 401 # HTTPBearer returns 401 if no header

def test_me_endpoint_invalid_token(mock_firebase_auth):
    mock_firebase_auth.side_effect = Exception("Invalid token")
    response = client.get("/web/me", headers={"Authorization": "Bearer invalid-token"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid authentication credentials"

def test_me_endpoint_success(mock_firebase_auth):
    # Mock decoded claims
    mock_firebase_auth.return_value = {
        "uid": "test-uid-123",
        "email": "test_user@agentix.ai",
        "role": "admin",
        "permissions": ["read", "chat", "manage"]
    }
    
    response = client.get("/web/me", headers={"Authorization": "Bearer valid-token"})
    assert response.status_code == 200
    data = response.json()
    assert data["uid"] == "test-uid-123"
    assert data["role"] == "admin"
    assert data["email"] == "test_user@agentix.ai"

def test_chat_endpoint_auth_required(mock_firebase_auth):
    # Mock success for chat
    mock_firebase_auth.return_value = {
        "uid": "test-uid-123",
        "email": "test_user@agentix.ai"
    }
    
    # We also need to mock the agentix_client services used in web_chat
    with patch("gateway.routers.web.create_session") as mock_create_session:
        mock_create_session.return_value = "session-123"
        
        with patch("gateway.routers.web.stream_chat") as mock_stream_chat:
            # Mock async generator
            async def mock_stream():
                yield {"event": "start"}
                yield {"event": "message", "text": "Hello"}
            
            mock_stream_chat.return_value = mock_stream()
            
            response = client.post(
                "/web/chat", 
                json={"message": "Hi"},
                headers={"Authorization": "Bearer some-token"}
            )
            
            assert response.status_code == 200
            # StreamingResponse content is a bit harder to check with TestClient but we can check if it started
            assert "data: " in response.text
