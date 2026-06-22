"""
Gateway to query Agentix core sessions and session_events tables.
Isolates AttackSimulator from direct Agentix database dependencies.
"""

import uuid
from typing import Any

import structlog
from attack_simulator.models import db_repo

logger = structlog.get_logger(__name__)


class AgentixSessionGateway:
    """
    Gateway to query Agentix sessions and session events.
    """

    async def get_session_status(self, session_id: str, conn: Any | None = None) -> str | None:
        """
        Retrieves the status of an Agentix session.
        """
        sess_uuid = uuid.UUID(session_id)
        if conn is not None:
            row = await conn.fetchrow("SELECT status FROM sessions WHERE id = $1", sess_uuid)
            return row["status"] if row else None

        pool = await db_repo.get_pool()
        async with pool.acquire() as c:
            row = await c.fetchrow("SELECT status FROM sessions WHERE id = $1", sess_uuid)
            return row["status"] if row else None

    async def get_session_events(self, session_id: str, conn: Any | None = None) -> list[dict[str, Any]]:
        """
        Retrieves event logs for a given session.
        """
        sess_uuid = uuid.UUID(session_id)
        if conn is not None:
            rows = await conn.fetch(
                """
                SELECT event_type, actor, content, metadata 
                FROM session_events 
                WHERE session_id = $1 
                ORDER BY id ASC
                """,
                sess_uuid,
            )
        else:
            pool = await db_repo.get_pool()
            async with pool.acquire() as c:
                rows = await c.fetch(
                    """
                    SELECT event_type, actor, content, metadata 
                    FROM session_events 
                    WHERE session_id = $1 
                    ORDER BY id ASC
                    """,
                    sess_uuid,
                )
        return [dict(row) for row in rows]

    async def get_session_details(self, session_id: str) -> dict[str, Any] | None:
        """
        Retrieves all details for an Agentix session.
        """
        try:
            sess_uuid = uuid.UUID(session_id)
            pool = await db_repo.get_pool()
            async with pool.acquire() as conn:
                row = await conn.fetchrow("SELECT * FROM sessions WHERE id = $1", sess_uuid)
                if row:
                    d = dict(row)
                    d["id"] = str(d["id"])
                    return d
            return None
        except Exception as e:
            logger.error("agentix_gateway.get_session_details_failed", session_id=session_id, error=str(e))
            return None
