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
async def test_list_sessions_gateway_agent_filter(client):
    token = create_access_token(
        data={"uid": "test-user-123", "email": "test-user@agentix.ai", "role": "admin", "permissions": ["read", "chat"]}
    )

    with patch("gateway.services.agentix_client.list_sessions", new_callable=AsyncMock) as mock_list_sessions:
        mock_list_sessions.return_value = {
            "sessions": [],
            "total_count": 0,
        }

        response = client.get(
            "/web/sessions?agent_name=soc_analyst",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["sessions"] == []
        assert data["total_count"] == 0
        mock_list_sessions.assert_called_once_with(
            owner_id=None,
            source=None,
            status=None,
            search=None,
            agent_name="soc_analyst",
            limit=50,
            offset=0,
        )
