from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from agentix.core.cleanup import cleanup_expired_workspaces, run_periodic_cleanup


@pytest.fixture
def mock_now():
    # Fix the current time for predictable tests
    fixed_now = datetime(2026, 5, 28, 12, 0, 0, tzinfo=UTC)
    with patch("agentix.core.cleanup.datetime") as dt_mock:
        dt_mock.now.return_value = fixed_now
        dt_mock.fromisoformat = datetime.fromisoformat
        yield fixed_now

@pytest.mark.asyncio
async def test_cleanup_expired_workspaces(mock_now):
    with patch("agentix.core.cleanup.SessionWorkspace.list_sessions") as mock_list, \
         patch("agentix.core.cleanup.SessionWorkspace.from_session_id") as mock_from_id, \
         patch("agentix.core.cleanup.settings") as mock_settings:
        
        mock_settings.agentix_session_ttl_hours = 2.0
        mock_settings.agentix_session_destroy_on_expire = True
        
        # 3 sessions: 
        # sid_active_fresh -> active, 1 hr old -> ignore
        # sid_active_old -> active, 3 hrs old -> cleanup
        # sid_cleaned_old -> cleaned, 3 hrs since cleanup -> destroy
        mock_list.return_value = ["sid_active_fresh", "sid_active_old", "sid_cleaned_old", "sid_no_meta", "sid_error"]
        
        def mock_from_session_id_side_effect(sid):
            ws = MagicMock()
            ws.cleanup = AsyncMock()
            ws.destroy = AsyncMock()
            
            if sid == "sid_active_fresh":
                created = (mock_now - timedelta(hours=1)).isoformat()
                ws.get_metadata.return_value = {"created_at": created, "status": "active"}
                return ws
            elif sid == "sid_active_old":
                created = (mock_now - timedelta(hours=3)).isoformat()
                ws.get_metadata.return_value = {"created_at": created, "status": "active"}
                return ws
            elif sid == "sid_cleaned_old":
                created = (mock_now - timedelta(hours=6)).isoformat()
                cleaned_time = (mock_now - timedelta(hours=3)).isoformat()
                ws.get_metadata.return_value = {
                    "created_at": created, 
                    "status": "cleaned",
                    "cleaned_at": cleaned_time
                }
                return ws
            elif sid == "sid_no_meta":
                ws.get_metadata.return_value = {}
                return ws
            elif sid == "sid_error":
                ws.get_metadata.side_effect = Exception("Mock DB error")
                return ws
            return None
            
        mock_from_id.side_effect = mock_from_session_id_side_effect
        
        summary = await cleanup_expired_workspaces()
        
        assert summary["total_scanned"] == 5
        assert summary["cleaned"] == 1
        assert summary["destroyed"] == 1
        assert summary["errors"] == 1
        assert "sid_active_old" in summary["cleaned_sessions"]
        assert "sid_cleaned_old" in summary["destroyed_sessions"]
        assert summary["error_details"][0]["session_id"] == "sid_error"

@pytest.mark.asyncio
async def test_run_periodic_cleanup():
    # Test that it runs at least once before we cancel it
    with patch("agentix.core.cleanup.cleanup_expired_workspaces", new_callable=AsyncMock) as mock_clean, \
         patch("agentix.core.cleanup.asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
        
        # We raise CancelledError on the first sleep to break the infinite loop
        import asyncio
        mock_sleep.side_effect = asyncio.CancelledError()
        
        try:
            await run_periodic_cleanup(interval_seconds=1)
        except asyncio.CancelledError:
            pass
            
        mock_clean.assert_called_once()
        mock_sleep.assert_called_once_with(1)
