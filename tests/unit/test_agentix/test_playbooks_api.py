import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

# Add src/Agentix and src/AgenticCommon to sys.path
root_dir = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(root_dir / "src" / "Agentix"))
sys.path.insert(0, str(root_dir / "src" / "AgenticCommon"))

with patch("gateway.security.auth.auth_store.setup_db", new_callable=AsyncMock):
    from gateway.main import app
    from gateway.security.auth import create_access_token


@pytest.fixture
def client():
    c = TestClient(app)
    c.cookies.clear()
    return c


@pytest.mark.asyncio
async def test_get_playbook_details_gateway_success(client):
    # Generate a valid JWT token
    token = create_access_token(
        data={"uid": "test-user-123", "email": "test-user@agentix.ai", "role": "admin", "permissions": ["read", "chat"]}
    )

    # Mock gateway's agentix_client.get_playbook_details
    with patch("gateway.services.agentix_client.get_playbook_details", new_callable=AsyncMock) as mock_get_details:
        mock_get_details.return_value = {
            "id": "PB-001",
            "name": "OS Credential Dumping – /etc/shadow Access",
            "steps": []
        }

        response = client.get("/web/playbooks/PB-001", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == "PB-001"
        assert data["name"] == "OS Credential Dumping – /etc/shadow Access"
        mock_get_details.assert_called_once_with("PB-001")


@pytest.mark.asyncio
async def test_get_playbook_summary_gateway_success(client):
    # Generate a valid JWT token
    token = create_access_token(
        data={"uid": "test-user-123", "email": "test-user@agentix.ai", "role": "admin", "permissions": ["read", "chat"]}
    )

    # Mock gateway's agentix_client.get_playbooks_summary
    with patch("gateway.services.agentix_client.get_playbooks_summary", new_callable=AsyncMock) as mock_get_summary:
        mock_get_summary.return_value = [
            {"id": "PB-001", "name": "OS Credential Dumping – /etc/shadow Access", "severity": "HIGH"}
        ]

        response = client.get("/web/playbooks/summary", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["id"] == "PB-001"
        mock_get_summary.assert_called_once()
