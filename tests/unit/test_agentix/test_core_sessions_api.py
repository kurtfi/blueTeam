import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

# Add src/Agentix and src/AgenticCommon to sys.path
root_dir = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(root_dir / "src" / "Agentix"))
sys.path.insert(0, str(root_dir / "src" / "AgenticCommon"))

from agentix.api.server import app

client = TestClient(app)


@pytest.mark.asyncio
async def test_list_sessions_core_agent_filter():
    with (
        patch("agentix.api.routes.sessions.postgres_session_repo.count_sessions", new_callable=AsyncMock) as mock_count,
        patch("agentix.api.routes.sessions.postgres_session_repo.list_sessions", new_callable=AsyncMock) as mock_list,
        patch("agentix.api.internal_auth.settings") as mock_settings,
    ):
        mock_settings.agentix_internal_api_key = "test-secret-key"
        mock_count.return_value = 0
        mock_list.return_value = []

        response = client.get(
            "/v1/sessions?agent_name=simulation_analyst", headers={"X-Internal-Api-Key": "test-secret-key"}
        )

        assert response.status_code == 200
        assert response.json() == []
        mock_count.assert_called_once_with(
            source=None,
            status=None,
            owner_id=None,
            search=None,
            agent_name="simulation_analyst",
        )
        mock_list.assert_called_once_with(
            source=None,
            status=None,
            owner_id=None,
            search=None,
            agent_name="simulation_analyst",
            limit=50,
            offset=0,
        )
