import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

# Add src/Agentix and src/AgenticCommon to sys.path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir))
sys.path.insert(0, str(root_dir.parent / "AgenticCommon"))

# Mock auth_store.setup_db during module load before importing app to avoid database connection
with patch("gateway.security.auth.auth_store.setup_db", new_callable=AsyncMock) as mock_setup:
    from gateway.main import app
    from gateway.security.auth import create_access_token, hash_password


@pytest.fixture
def client():
    c = TestClient(app)
    c.cookies.clear()
    return c


def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "Agentix Gateway"}


def test_me_endpoint_unauthorized(client):
    response = client.get("/web/me")
    assert response.status_code == 401


def test_me_endpoint_invalid_token(client):
    response = client.get("/web/me", headers={"Authorization": "Bearer invalid-token"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid authentication credentials"


@patch("gateway.routers.web.auth_store.get_user_by_username", new_callable=AsyncMock)
def test_login_endpoint_success(mock_get_user, client):
    pw_hash = hash_password("test-pass")
    mock_get_user.return_value = {
        "username": "test-user",
        "password_hash": pw_hash,
        "email": "test-user@agentix.ai",
        "role": "admin",
        "permissions": '["read", "chat"]',
    }

    response = client.post("/web/login", json={"username": "test-user", "password": "test-pass"})
    assert response.status_code == 200
    data = response.json()
    assert data == {"status": "success", "message": "Logged in successfully"}
    assert "agentix_access_token" in response.cookies


@patch("gateway.routers.web.auth_store.get_user_by_username", new_callable=AsyncMock)
def test_login_endpoint_invalid_credentials(mock_get_user, client):
    mock_get_user.return_value = None

    response = client.post("/web/login", json={"username": "test-user", "password": "test-pass"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect username or password"


def test_me_endpoint_success(client):
    # Generate a valid JWT token
    token = create_access_token(
        data={"uid": "test-user-123", "email": "test-user@agentix.ai", "role": "admin", "permissions": ["read", "chat"]}
    )

    response = client.get("/web/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    data = response.json()
    assert data["uid"] == "test-user-123"
    assert data["role"] == "admin"
    assert data["email"] == "test-user@agentix.ai"


def test_chat_endpoint_success(client):
    # Generate a valid JWT token
    token = create_access_token(
        data={"uid": "test-user-123", "email": "test-user@agentix.ai", "role": "admin", "permissions": ["read", "chat"]}
    )

    # Mock the downstream agentix_client services
    with patch("gateway.routers.web.create_session", new_callable=AsyncMock) as mock_create_session:
        mock_create_session.return_value = "session-123"

        with patch("gateway.routers.web.stream_chat") as mock_stream_chat:

            async def mock_stream(*args, **kwargs):
                yield {"type": "step", "content": "mock step"}
                yield {"type": "answer", "content": "Hello there"}

            mock_stream_chat.return_value = mock_stream()

            response = client.post("/web/chat", json={"message": "Hi"}, headers={"Authorization": f"Bearer {token}"})

            assert response.status_code == 200
            assert "data: " in response.text
