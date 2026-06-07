"""
SessionWorkspace — per-session isolated file workspace.

Each session gets a dedicated directory tree under WORKSPACE_ROOT/sessions/{session_id}/
with standardised sub-directories for different artifact types.

Security
--------
- All paths are resolved and checked against the session root to prevent traversal.
- Only the session owner can access the workspace (validated via owner_id).
- Disk quota is enforced on writes to prevent runaway storage consumption.

Cleanup Strategy
----------------
On expiration / manual destroy:
  - ``temp/`` and ``downloads/`` are **deleted**.
  - ``outputs/`` is **preserved** for audit trail / later retrieval.
"""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from agentic_common.settings import settings

logger = structlog.get_logger(__name__)

# Standard sub-directories created for every session.
_SUBDIRS: tuple[str, ...] = ("downloads", "outputs", "uploads", "temp")

# Directories cleaned up on session expiration (outputs intentionally kept).
_CLEANUP_SUBDIRS: tuple[str, ...] = ("temp", "downloads")


def _workspace_root() -> Path:
    """Return the resolved base path for all session workspaces."""
    custom = settings.agentix_session_workspace_root
    if custom:
        return Path(custom).resolve()
    # Default: alongside the global workspace root.
    base = settings.agentix_workspace_root
    if base:
        return Path(base).resolve() / "sessions"
    return Path.cwd().resolve() / "sessions"


class SessionWorkspace:
    """
    Per-session isolated file workspace.

    Attributes
    ----------
    session_id : str
        UUID of the session.
    owner_id : str
        Identifier of the user who owns this session.
    root : Path
        Absolute path to the session directory.
    """

    def __init__(self, session_id: str, owner_id: str = "anonymous") -> None:
        self.session_id = session_id
        self.owner_id = owner_id
        self.root: Path = _workspace_root() / session_id
        self._meta_path: Path = self.root / ".session_meta.json"
        self._quota_bytes: int = settings.agentix_session_quota_mb * 1024 * 1024

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def initialize(self) -> Path:
        """
        Create the session directory tree and write the metadata file.

        Returns:
            The absolute ``root`` path of this session workspace.
        """
        self.root.mkdir(parents=True, exist_ok=True)
        for sub in _SUBDIRS:
            (self.root / sub).mkdir(exist_ok=True)

        meta = {
            "session_id": self.session_id,
            "owner_id": self.owner_id,
            "created_at": datetime.now(UTC).isoformat(),
            "status": "active",
            "quota_bytes": self._quota_bytes,
        }
        self._meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

        logger.info(
            "workspace.initialized",
            session_id=self.session_id,
            root=str(self.root),
            owner=self.owner_id,
        )
        return self.root

    # ------------------------------------------------------------------
    # Path resolution & security
    # ------------------------------------------------------------------

    def resolve_path(
        self,
        relative_path: str,
        subdirectory: str = "outputs",
    ) -> Path:
        """
        Resolve *relative_path* inside a session subdirectory.

        Raises ``PermissionError`` if the resolved path escapes the session root.

        Args:
            relative_path: Relative (or absolute) path supplied by a tool.
            subdirectory:  Target subdirectory within the session workspace
                           (``downloads``, ``outputs``, ``uploads``, ``temp``).

        Returns:
            Resolved absolute path guaranteed to reside inside the session root.
        """
        base = self.root / subdirectory
        resolved = (base / relative_path).resolve()

        if not resolved.is_relative_to(self.root.resolve()):
            raise PermissionError(f"Access denied: path '{relative_path}' is outside the allowed workspace boundary.")
        return resolved

    def contains(self, absolute_path: str | Path) -> bool:
        """Return True if *absolute_path* resides inside this session workspace."""
        try:
            return Path(absolute_path).resolve().is_relative_to(self.root.resolve())
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Access control
    # ------------------------------------------------------------------

    def validate_access(self, owner_id: str) -> bool:
        """
        Verify that *owner_id* matches the session owner.

        For the initial ``anonymous`` default, all access is granted.
        """
        if self.owner_id == "anonymous":
            return True
        return self.owner_id == owner_id

    # ------------------------------------------------------------------
    # Quota
    # ------------------------------------------------------------------

    def get_usage_bytes(self) -> int:
        """Calculate total disk usage of the session workspace in bytes."""
        total = 0
        for f in self.root.rglob("*"):
            if f.is_file():
                total += f.stat().st_size
        return total

    async def get_usage(self) -> dict[str, Any]:
        """Return usage statistics for this workspace."""
        used = self.get_usage_bytes()
        return {
            "session_id": self.session_id,
            "used_bytes": used,
            "quota_bytes": self._quota_bytes,
            "used_mb": round(used / (1024 * 1024), 2),
            "quota_mb": settings.agentix_session_quota_mb,
            "usage_percent": round((used / self._quota_bytes) * 100, 1) if self._quota_bytes else 0,
        }

    def check_quota(self, additional_bytes: int = 0) -> None:
        """
        Raise ``PermissionError`` if writing *additional_bytes* would exceed quota.
        """
        if self._quota_bytes <= 0:
            return  # Unlimited
        current = self.get_usage_bytes()
        if current + additional_bytes > self._quota_bytes:
            raise PermissionError(
                f"Session workspace quota exceeded: {current + additional_bytes} / {self._quota_bytes} bytes."
            )

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------

    def get_metadata(self) -> dict[str, Any]:
        """Read and return the session metadata from disk."""
        if not self._meta_path.exists():
            return {}
        return json.loads(self._meta_path.read_text(encoding="utf-8"))

    def update_metadata(self, **kwargs: Any) -> None:
        """Merge additional key-value pairs into the session metadata file."""
        meta = self.get_metadata()
        meta.update(kwargs)
        self._meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    # ------------------------------------------------------------------
    # Cleanup & Destroy
    # ------------------------------------------------------------------

    async def cleanup(self) -> dict[str, Any]:
        """
        Selective cleanup: delete ``temp/`` and ``downloads/``, keep ``outputs/``.

        Returns:
            Summary of what was cleaned.
        """
        freed = 0
        dirs_cleaned = []

        for sub in _CLEANUP_SUBDIRS:
            subdir = self.root / sub
            if subdir.exists() and subdir.is_dir():
                for item in subdir.rglob("*"):
                    if item.is_file():
                        freed += item.stat().st_size
                shutil.rmtree(subdir)
                subdir.mkdir(exist_ok=True)  # Re-create empty dir
                dirs_cleaned.append(sub)

        self.update_metadata(status="cleaned", cleaned_at=datetime.now(UTC).isoformat())

        logger.info(
            "workspace.cleanup",
            session_id=self.session_id,
            freed_bytes=freed,
            dirs=dirs_cleaned,
        )
        return {
            "session_id": self.session_id,
            "freed_bytes": freed,
            "freed_mb": round(freed / (1024 * 1024), 2),
            "dirs_cleaned": dirs_cleaned,
        }

    async def destroy(self) -> None:
        """
        Completely remove the session workspace directory tree.

        Use with caution — this deletes **everything** including ``outputs/``.
        """
        if self.root.exists():
            shutil.rmtree(self.root)
            logger.info("workspace.destroyed", session_id=self.session_id)

    # ------------------------------------------------------------------
    # Class-level helpers
    # ------------------------------------------------------------------

    @classmethod
    def from_session_id(cls, session_id: str) -> SessionWorkspace | None:
        """
        Reconstruct a SessionWorkspace from an existing directory on disk.

        Returns ``None`` if the session directory does not exist.
        """
        root = _workspace_root() / session_id
        if not root.exists():
            return None

        meta_path = root / ".session_meta.json"
        owner_id = "anonymous"
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                owner_id = meta.get("owner_id", "anonymous")
            except (json.JSONDecodeError, OSError):
                pass

        ws = cls(session_id=session_id, owner_id=owner_id)
        return ws

    @classmethod
    def list_sessions(cls) -> list[str]:
        """Return a list of all session IDs with directories on disk."""
        base = _workspace_root()
        if not base.exists():
            return []
        return [d.name for d in base.iterdir() if d.is_dir() and not d.name.startswith(".")]
