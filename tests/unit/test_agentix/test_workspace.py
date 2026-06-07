"""
Unit tests for the SessionWorkspace module.

Covers:
 - Workspace initialisation and directory creation
 - Metadata read / write
 - Path resolution and traversal prevention
 - Access control (owner validation)
 - Quota enforcement
 - Selective cleanup (temp + downloads deleted, outputs preserved)
 - Full destroy
 - Class-level helpers (from_session_id, list_sessions)
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

# Patch settings before importing workspace module
os.environ.setdefault("AGENTIX_SESSION_WORKSPACE_ENABLED", "true")
os.environ.setdefault("AGENTIX_SESSION_QUOTA_MB", "1")  # 1 MB for tests


@pytest.fixture
def workspace_root(tmp_path: Path):
    """Provide a temporary workspace root and patch settings to use it."""
    sessions_dir = tmp_path / "sessions"
    sessions_dir.mkdir()

    # Patch the settings at module level so _workspace_root() uses our temp dir.
    from agentic_common import settings as settings_mod
    original_root = settings_mod.settings.agentix_session_workspace_root
    settings_mod.settings.agentix_session_workspace_root = str(sessions_dir)
    original_quota = settings_mod.settings.agentix_session_quota_mb
    settings_mod.settings.agentix_session_quota_mb = 1

    yield sessions_dir

    # Restore
    settings_mod.settings.agentix_session_workspace_root = original_root
    settings_mod.settings.agentix_session_quota_mb = original_quota


@pytest.fixture
def session_id() -> str:
    return "test-session-001"


# ------------------------------------------------------------------
# Initialisation
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_initialize_creates_directory_tree(workspace_root: Path, session_id: str):
    from agentic_common.workspace import SessionWorkspace

    ws = SessionWorkspace(session_id=session_id, owner_id="user-42")
    root = await ws.initialize()

    assert root.exists()
    assert (root / "downloads").is_dir()
    assert (root / "outputs").is_dir()
    assert (root / "uploads").is_dir()
    assert (root / "temp").is_dir()
    assert (root / ".session_meta.json").exists()


@pytest.mark.asyncio
async def test_initialize_writes_metadata(workspace_root: Path, session_id: str):
    from agentic_common.workspace import SessionWorkspace

    ws = SessionWorkspace(session_id=session_id, owner_id="user-42")
    await ws.initialize()

    meta = ws.get_metadata()
    assert meta["session_id"] == session_id
    assert meta["owner_id"] == "user-42"
    assert meta["status"] == "active"
    assert "created_at" in meta
    assert "quota_bytes" in meta


# ------------------------------------------------------------------
# Path resolution & security
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resolve_path_within_workspace(workspace_root: Path, session_id: str):
    from agentic_common.workspace import SessionWorkspace

    ws = SessionWorkspace(session_id=session_id)
    await ws.initialize()

    resolved = ws.resolve_path("report.txt", subdirectory="outputs")
    assert str(resolved).startswith(str(ws.root))
    assert resolved.name == "report.txt"


@pytest.mark.asyncio
async def test_resolve_path_traversal_blocked(workspace_root: Path, session_id: str):
    from agentic_common.workspace import SessionWorkspace

    ws = SessionWorkspace(session_id=session_id)
    await ws.initialize()

    with pytest.raises(PermissionError, match="outside the allowed workspace boundary"):
        ws.resolve_path("../../etc/passwd", subdirectory="temp")


@pytest.mark.asyncio
async def test_resolve_path_prefix_traversal_blocked(workspace_root: Path):
    from agentic_common.workspace import SessionWorkspace

    # session-1 is a string prefix of session-10
    ws_a = SessionWorkspace(session_id="session-1")
    await ws_a.initialize()

    ws_b = SessionWorkspace(session_id="session-10")
    await ws_b.initialize()

    # Attempt to traverse from session-1 to session-10
    with pytest.raises(PermissionError, match="outside the allowed workspace boundary"):
        ws_a.resolve_path("../../session-10/malicious.txt", subdirectory="outputs")

    # Verify contains checks are also structurally locked
    target_path = ws_b.root / "outputs" / "malicious.txt"
    assert ws_a.contains(target_path) is False


@pytest.mark.asyncio
async def test_contains_checks_path_membership(workspace_root: Path, session_id: str):
    from agentic_common.workspace import SessionWorkspace

    ws = SessionWorkspace(session_id=session_id)
    await ws.initialize()

    inner = ws.root / "outputs" / "test.txt"
    assert ws.contains(inner) is True
    assert ws.contains("/etc/passwd") is False


# ------------------------------------------------------------------
# Access control
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_validate_access_matches_owner(workspace_root: Path, session_id: str):
    from agentic_common.workspace import SessionWorkspace

    ws = SessionWorkspace(session_id=session_id, owner_id="user-42")
    await ws.initialize()

    assert ws.validate_access("user-42") is True
    assert ws.validate_access("user-99") is False


@pytest.mark.asyncio
async def test_validate_access_anonymous_allows_all(workspace_root: Path, session_id: str):
    from agentic_common.workspace import SessionWorkspace

    ws = SessionWorkspace(session_id=session_id, owner_id="anonymous")
    await ws.initialize()

    assert ws.validate_access("anyone") is True
    assert ws.validate_access("user-42") is True


# ------------------------------------------------------------------
# Quota
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_check_quota_passes_within_limit(workspace_root: Path, session_id: str):
    from agentic_common.workspace import SessionWorkspace

    ws = SessionWorkspace(session_id=session_id)
    await ws.initialize()

    # Should not raise for a small amount
    ws.check_quota(additional_bytes=100)


@pytest.mark.asyncio
async def test_check_quota_fails_when_exceeded(workspace_root: Path, session_id: str):
    from agentic_common.workspace import SessionWorkspace

    ws = SessionWorkspace(session_id=session_id)
    await ws.initialize()

    # Quota is 1 MB = 1_048_576 bytes, asking for 2 MB should fail
    with pytest.raises(PermissionError, match="quota exceeded"):
        ws.check_quota(additional_bytes=2 * 1024 * 1024)


@pytest.mark.asyncio
async def test_get_usage_reports_correct(workspace_root: Path, session_id: str):
    from agentic_common.workspace import SessionWorkspace

    ws = SessionWorkspace(session_id=session_id)
    await ws.initialize()

    # Write a 1 KB file
    test_file = ws.root / "outputs" / "data.txt"
    test_file.write_text("x" * 1024)

    usage = await ws.get_usage()
    assert usage["used_bytes"] >= 1024
    assert usage["quota_mb"] == 1
    assert usage["session_id"] == session_id


# ------------------------------------------------------------------
# Cleanup
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cleanup_deletes_temp_and_downloads_keeps_outputs(
    workspace_root: Path, session_id: str
):
    from agentic_common.workspace import SessionWorkspace

    ws = SessionWorkspace(session_id=session_id)
    await ws.initialize()

    # Create files in each subdirectory
    (ws.root / "temp" / "scratch.tmp").write_text("temp data")
    (ws.root / "downloads" / "file.zip").write_text("downloaded")
    (ws.root / "outputs" / "report.md").write_text("important output")
    (ws.root / "uploads" / "input.csv").write_text("user upload")

    result = await ws.cleanup()

    # temp and downloads should be empty
    assert not list((ws.root / "temp").iterdir())
    assert not list((ws.root / "downloads").iterdir())
    # outputs and uploads should be preserved
    assert (ws.root / "outputs" / "report.md").exists()
    assert (ws.root / "uploads" / "input.csv").exists()

    assert result["freed_bytes"] > 0
    assert "temp" in result["dirs_cleaned"]
    assert "downloads" in result["dirs_cleaned"]

    # Metadata should be updated
    meta = ws.get_metadata()
    assert meta["status"] == "cleaned"
    assert "cleaned_at" in meta


# ------------------------------------------------------------------
# Destroy
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_destroy_removes_entire_workspace(workspace_root: Path, session_id: str):
    from agentic_common.workspace import SessionWorkspace

    ws = SessionWorkspace(session_id=session_id)
    await ws.initialize()

    assert ws.root.exists()
    await ws.destroy()
    assert not ws.root.exists()


# ------------------------------------------------------------------
# Class-level helpers
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_from_session_id_reconstructs_workspace(workspace_root: Path, session_id: str):
    from agentic_common.workspace import SessionWorkspace

    # Create a workspace first
    ws = SessionWorkspace(session_id=session_id, owner_id="user-42")
    await ws.initialize()

    # Reconstruct from disk
    ws2 = SessionWorkspace.from_session_id(session_id)
    assert ws2 is not None
    assert ws2.session_id == session_id
    assert ws2.owner_id == "user-42"
    assert ws2.root == ws.root


@pytest.mark.asyncio
async def test_from_session_id_returns_none_if_missing(workspace_root: Path):
    from agentic_common.workspace import SessionWorkspace

    ws = SessionWorkspace.from_session_id("nonexistent-session")
    assert ws is None


@pytest.mark.asyncio
async def test_list_sessions(workspace_root: Path):
    from agentic_common.workspace import SessionWorkspace

    ws1 = SessionWorkspace(session_id="session-a")
    ws2 = SessionWorkspace(session_id="session-b")
    await ws1.initialize()
    await ws2.initialize()

    sessions = SessionWorkspace.list_sessions()
    assert "session-a" in sessions
    assert "session-b" in sessions


# ------------------------------------------------------------------
# Metadata update
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_metadata_merges(workspace_root: Path, session_id: str):
    from agentic_common.workspace import SessionWorkspace

    ws = SessionWorkspace(session_id=session_id, owner_id="user-42")
    await ws.initialize()

    ws.update_metadata(custom_key="custom_value", status="in_progress")

    meta = ws.get_metadata()
    assert meta["custom_key"] == "custom_value"
    assert meta["status"] == "in_progress"
    # Original fields should be preserved
    assert meta["owner_id"] == "user-42"
    assert meta["session_id"] == session_id
