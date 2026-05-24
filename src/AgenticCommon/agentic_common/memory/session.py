"""
SessionStore — in-memory conversation history and session metadata.
"""
from __future__ import annotations

from typing import Any


class SessionStore:
    """
    Thread-safe, in-memory session store.
    """

    def __init__(self) -> None:
        self._history: dict[str, list[dict]] = {}
        self._metadata: dict[str, dict[str, Any]] = {}

    async def exists(self, session_id: str) -> bool:
        return session_id in self._history or session_id in self._metadata

    async def get_history(self, session_id: str) -> list[dict]:
        return list(self._history.get(session_id, []))

    async def append(
        self,
        session_id: str,
        user_message: str,
        assistant_message: str,
    ) -> None:
        if session_id not in self._history:
            self._history[session_id] = []
        self._history[session_id].append({"role": "user", "content": user_message})
        self._history[session_id].append(
            {"role": "assistant", "content": assistant_message}
        )

    async def clear(self, session_id: str) -> None:
        self._history.pop(session_id, None)
        self._metadata.pop(session_id, None)

    async def get_metadata(self, session_id: str) -> dict[str, Any]:
        return dict(self._metadata.get(session_id, {}))

    async def set_metadata(self, session_id: str, key: str, value: Any) -> None:
        if session_id not in self._metadata:
            self._metadata[session_id] = {}
        self._metadata[session_id][key] = value

    async def delete_metadata(self, session_id: str, key: str) -> bool:
        bucket = self._metadata.get(session_id)
        if bucket and key in bucket:
            del bucket[key]
            return True
        return False

    async def list_metadata_keys(self, session_id: str) -> list[str]:
        return list(self._metadata.get(session_id, {}).keys())
