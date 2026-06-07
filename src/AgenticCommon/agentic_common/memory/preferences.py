"""
PreferenceStore — persistent user preference management.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any


class PreferenceStore:
    """
    Key-value store for per-user preferences.
    """

    def __init__(self) -> None:
        self._store: dict[str, dict[str, Any]] = defaultdict(dict)

    async def get(self, user_id: str, key: str, default: Any = None) -> Any:
        return self._store[user_id].get(key, default)

    async def get_all(self, user_id: str) -> dict[str, Any]:
        return dict(self._store[user_id])

    async def set(self, user_id: str, key: str, value: Any) -> None:
        self._store[user_id][key] = value

    async def delete(self, user_id: str, key: str) -> None:
        self._store[user_id].pop(key, None)

    async def clear_user(self, user_id: str) -> None:
        self._store.pop(user_id, None)
