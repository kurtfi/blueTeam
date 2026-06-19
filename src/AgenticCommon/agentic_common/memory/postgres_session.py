"""
PostgreSQL Session Repository for persisting SOC sessions and agent audit trail events.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import asyncpg  # type: ignore[import-untyped]
import structlog

from agentic_common.settings import settings

logger = structlog.get_logger(__name__)


class PostgresSessionRepository:
    """
    Handles PostgreSQL persistence for Agentix sessions and events.
    """

    def __init__(self, pool: asyncpg.Pool | None = None) -> None:
        self._pool = pool

    async def get_pool(self) -> asyncpg.Pool:
        if self._pool is None:
            # strip +asyncpg for asyncpg library DSN compatibility
            dsn = settings.agentix_postgres_url.replace("+asyncpg", "")
            logger.info("postgres_session.connecting_db", dsn_masked=dsn.split("@")[-1])

            import asyncio

            max_retries = 3
            backoff = 1.0
            for attempt in range(1, max_retries + 1):
                try:
                    self._pool = await asyncpg.create_pool(dsn=dsn)
                    break
                except Exception as e:
                    if attempt == max_retries:
                        logger.critical(
                            "postgres_session.connection_failed_final",
                            error=str(e),
                            alert=True,
                            db_failure=True,
                        )
                        raise
                    logger.warning(
                        "postgres_session.connection_failed_retry",
                        error=str(e),
                        attempt=attempt,
                        next_retry_in=backoff,
                    )
                    await asyncio.sleep(backoff)
                    backoff *= 2
        return self._pool

    async def run_migrations(self) -> None:
        """
        Runs migrations from the migrations/ directory to set up the database.
        Finds all .sql files in migrations/, sorts them alphabetically, and runs them.
        """
        import os

        pool = await self.get_pool()

        current_dir = os.path.dirname(os.path.abspath(__file__))
        migration_dir = os.path.abspath(os.path.join(current_dir, "../../../../migrations"))

        if not os.path.exists(migration_dir):
            logger.error("postgres_session.migration_dir_not_found", path=migration_dir)
            return

        files = sorted([f for f in os.listdir(migration_dir) if f.endswith(".sql")])
        logger.info("postgres_session.found_migrations", files=files)

        async with pool.acquire() as conn:
            # ALTER TYPE ... ADD VALUE cannot be executed inside a transaction block, so run it beforehand
            try:
                await conn.execute("ALTER TYPE session_source ADD VALUE 'SIEM';")
            except Exception:
                # Ignore if it already exists or type is not created yet
                pass

            for file_name in files:
                file_path = os.path.join(migration_dir, file_name)
                logger.info("postgres_session.running_migration", file=file_name)
                with open(file_path, "r", encoding="utf-8") as f:
                    sql = f.read()
                try:
                    async with conn.transaction():
                        await conn.execute(sql)
                except Exception as e:
                    logger.error("postgres_session.migration_failed", file=file_name, error=str(e))
                    raise
        logger.info("postgres_session.migrations_completed")

    async def create_session(
        self,
        *,
        display_name: str,
        source: str,  # SIEM | USER | SYSTEM
        owner_id: str = "anonymous",
        agent_name: str | None = None,
        siem_rule_id: str | None = None,
        siem_rule_desc: str | None = None,
        siem_severity: int | None = None,
        source_ip: str | None = None,
        mitre_ids: list[str] | None = None,
        alert_payload: dict | None = None,
        session_id: str | None = None,
    ) -> str:
        """
        Create a new persistent session in PostgreSQL.
        Returns the session ID (string representation of UUID).
        """
        # Truncate input string arguments to match column character limits
        display_name = display_name[:255]
        owner_id = owner_id[:255]
        if agent_name:
            agent_name = agent_name[:255]
        if siem_rule_id:
            siem_rule_id = str(siem_rule_id)[:255]
        if siem_rule_desc:
            siem_rule_desc = siem_rule_desc[:1000]
        if source_ip:
            source_ip = source_ip[:255]

        pool = await self.get_pool()
        sess_id = uuid.UUID(session_id) if session_id else uuid.uuid4()

        payload_json = json.dumps(alert_payload) if alert_payload is not None else None

        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO sessions (
                    id, display_name, source, owner_id, agent_name,
                    siem_rule_id, siem_rule_desc, siem_severity,
                    source_ip, mitre_ids, alert_payload, status, created_at, updated_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'ACTIVE', NOW(), NOW())
                """,
                sess_id,
                display_name,
                source,
                owner_id,
                agent_name,
                siem_rule_id,
                siem_rule_desc,
                siem_severity,
                source_ip,
                mitre_ids,
                payload_json,
            )

        logger.info("postgres_session.created", session_id=str(sess_id), display_name=display_name)
        return str(sess_id)

    async def update_status(
        self,
        session_id: str,
        status: str,
        verdict: str | None = None,
    ) -> None:
        """
        Updates session status, verdict and sets completed_at if COMPLETED, FAILED, or ARCHIVED.
        """
        pool = await self.get_pool()
        sess_uuid = uuid.UUID(session_id)

        now = datetime.now(UTC)
        completed_at = now if status in ("COMPLETED", "FAILED", "ARCHIVED") else None
        deleted_at = now if status == "ARCHIVED" else None

        async with pool.acquire() as conn:
            if completed_at:
                if deleted_at:
                    await conn.execute(
                        """
                        UPDATE sessions 
                        SET status = $2, verdict = COALESCE($3, verdict), completed_at = $4, deleted_at = $5, updated_at = NOW()
                        WHERE id = $1
                        """,
                        sess_uuid,
                        status,
                        verdict,
                        completed_at,
                        deleted_at,
                    )
                else:
                    await conn.execute(
                        """
                        UPDATE sessions 
                        SET status = $2, verdict = COALESCE($3, verdict), completed_at = $4, updated_at = NOW()
                        WHERE id = $1
                        """,
                        sess_uuid,
                        status,
                        verdict,
                        completed_at,
                    )
            else:
                await conn.execute(
                    """
                    UPDATE sessions 
                    SET status = $2, verdict = COALESCE($3, verdict), updated_at = NOW()
                    WHERE id = $1
                    """,
                    sess_uuid,
                    status,
                    verdict,
                )

        logger.info("postgres_session.status_updated", session_id=session_id, status=status, verdict=verdict)

    async def update_stats(
        self,
        session_id: str,
        *,
        message_count: int | None = None,
        tool_calls: int | None = None,
        hitl_count: int | None = None,
        langfuse_trace_id: str | None = None,
    ) -> None:
        """
        Updates counters and Langfuse trace ID.
        """
        pool = await self.get_pool()
        sess_uuid = uuid.UUID(session_id)

        updates = []
        params: list[Any] = [sess_uuid]

        if message_count is not None:
            params.append(message_count)
            updates.append(f"message_count = ${len(params)}")

        if tool_calls is not None:
            params.append(tool_calls)
            updates.append(f"tool_calls = ${len(params)}")

        if hitl_count is not None:
            params.append(hitl_count)
            updates.append(f"hitl_count = ${len(params)}")

        if langfuse_trace_id is not None:
            params.append(langfuse_trace_id)
            updates.append(f"langfuse_trace_id = ${len(params)}")

        if not updates:
            return

        query = f"UPDATE sessions SET {', '.join(updates)}, updated_at = NOW() WHERE id = $1"
        async with pool.acquire() as conn:
            await conn.execute(query, *params)

    async def increment_stats(
        self,
        session_id: str,
        *,
        message_count: int = 0,
        tool_calls: int = 0,
        hitl_count: int = 0,
    ) -> None:
        """
        Increment counters atomically in PostgreSQL.
        """
        pool = await self.get_pool()
        sess_uuid = uuid.UUID(session_id)
        async with pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE sessions 
                SET message_count = message_count + $2,
                    tool_calls = tool_calls + $3,
                    hitl_count = hitl_count + $4,
                    updated_at = NOW()
                WHERE id = $1
                """,
                sess_uuid,
                message_count,
                tool_calls,
                hitl_count,
            )

    async def get_session(self, session_id: str) -> dict[str, Any] | None:
        """
        Retrieve a single session by its UUID.
        """
        pool = await self.get_pool()
        sess_uuid = uuid.UUID(session_id)

        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM sessions WHERE id = $1",
                sess_uuid,
            )
            if row:
                d = dict(row)
                # Parse alert_payload if present
                if d.get("alert_payload"):
                    d["alert_payload"] = json.loads(d["alert_payload"])
                # Convert UUID and datetime to standard formats if necessary, asyncpg returns UUID/datetime objects which is fine
                d["id"] = str(d["id"])
                return d
        return None

    async def count_sessions(
        self,
        *,
        source: str | None = None,
        status: str | None = None,
        owner_id: str | None = None,
        search: str | None = None,
        include_archived: bool = False,
    ) -> int:
        """
        Count total matching sessions for pagination calculation.
        """
        pool = await self.get_pool()

        where_clauses = []
        params: list[Any] = []

        if not include_archived:
            where_clauses.append("deleted_at IS NULL AND status != 'ARCHIVED'")

        if source:
            params.append(source)
            where_clauses.append(f"source = ${len(params)}")

        if status:
            params.append(status)
            where_clauses.append(f"status = ${len(params)}")

        if owner_id:
            params.append(owner_id)
            where_clauses.append(f"owner_id = ${len(params)}")

        if search:
            params.append(f"%{search}%")
            param_idx = len(params)
            where_clauses.append(
                f"(display_name ILIKE ${param_idx} OR source_ip ILIKE ${param_idx} OR siem_rule_id ILIKE ${param_idx})"
            )

        where_str = ""
        if where_clauses:
            where_str = "WHERE " + " AND ".join(where_clauses)

        query = f"SELECT COUNT(*) FROM sessions {where_str}"

        async with pool.acquire() as conn:
            count = await conn.fetchval(query, *params)
        return count or 0

    async def list_sessions(
        self,
        *,
        source: str | None = None,
        status: str | None = None,
        owner_id: str | None = None,
        search: str | None = None,
        limit: int = 50,
        offset: int = 0,
        include_archived: bool = False,
    ) -> list[dict[str, Any]]:
        """
        List sessions with filtering and pagination. Soft-deleted sessions are excluded by default.
        """
        pool = await self.get_pool()

        where_clauses = []
        params: list[Any] = []

        if not include_archived:
            where_clauses.append("deleted_at IS NULL AND status != 'ARCHIVED'")

        if source:
            params.append(source)
            where_clauses.append(f"source = ${len(params)}")

        if status:
            params.append(status)
            where_clauses.append(f"status = ${len(params)}")

        if owner_id:
            params.append(owner_id)
            where_clauses.append(f"owner_id = ${len(params)}")

        if search:
            params.append(f"%{search}%")
            param_idx = len(params)
            where_clauses.append(
                f"(display_name ILIKE ${param_idx} OR source_ip ILIKE ${param_idx} OR siem_rule_id ILIKE ${param_idx})"
            )

        where_str = ""
        if where_clauses:
            where_str = "WHERE " + " AND ".join(where_clauses)

        params.append(limit)
        limit_param = f"${len(params)}"
        params.append(offset)
        offset_param = f"${len(params)}"

        query = f"""
            SELECT * FROM sessions
            {where_str}
            ORDER BY created_at DESC
            LIMIT {limit_param} OFFSET {offset_param}
        """

        async with pool.acquire() as conn:
            rows = await conn.fetch(query, *params)

        results = []
        for row in rows:
            d = dict(row)
            if d.get("alert_payload"):
                d["alert_payload"] = json.loads(d["alert_payload"])
            d["id"] = str(d["id"])
            results.append(d)

        return results

    async def add_event(
        self,
        session_id: str,
        event_type: str,
        actor: str,
        content: str | None = None,
        metadata: dict | None = None,
    ) -> None:
        """
        Append an event to the session audit trail.
        """
        # Truncate input string arguments to match column character limits
        event_type = event_type[:100]
        actor = actor[:100]
        if content:
            content = content[:1000]

        pool = await self.get_pool()
        sess_uuid = uuid.UUID(session_id)
        metadata_json = json.dumps(metadata) if metadata is not None else None

        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO session_events (session_id, event_type, actor, content, metadata, created_at)
                VALUES ($1, $2, $3, $4, $5, NOW())
                """,
                sess_uuid,
                event_type,
                actor,
                content,
                metadata_json,
            )
        logger.debug("postgres_session.event_added", session_id=session_id, event_type=event_type)

    async def get_events(self, session_id: str, limit: int = 100) -> list[dict[str, Any]]:
        """
        Get all events for a session, ordered chronologically.
        """
        pool = await self.get_pool()
        sess_uuid = uuid.UUID(session_id)

        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT * FROM session_events 
                WHERE session_id = $1 
                ORDER BY created_at ASC 
                LIMIT $2
                """,
                sess_uuid,
                limit,
            )

        results = []
        for row in rows:
            d = dict(row)
            if d.get("metadata"):
                d["metadata"] = json.loads(d["metadata"])
            d["session_id"] = str(d["session_id"])
            results.append(d)
        return results

    async def get_session_stats(self) -> dict[str, Any]:
        """
        Get aggregated session stats for the dashboard.
        """
        pool = await self.get_pool()

        async with pool.acquire() as conn:
            # Basic counts (excluding soft-deleted/archived)
            counts = await conn.fetchrow(
                """
                SELECT 
                    COUNT(*) FILTER (WHERE status = 'ACTIVE') as active_sessions,
                    COUNT(*) FILTER (WHERE status = 'WAITING_APPROVAL') as pending_hitl,
                    COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '24 hours') as created_last_24h,
                    COUNT(*) FILTER (WHERE status = 'COMPLETED') as completed_sessions,
                    COUNT(*) FILTER (WHERE source = 'SIEM') as siem_sessions,
                    COUNT(*) FILTER (WHERE source = 'USER') as user_sessions
                FROM sessions
                WHERE deleted_at IS NULL AND status != 'ARCHIVED'
                """
            )

            # SIEM specific metrics
            verdicts = await conn.fetchrow(
                """
                SELECT
                    COUNT(*) FILTER (WHERE verdict = 'TRUE_POSITIVE') as true_positives,
                    COUNT(*) FILTER (WHERE verdict = 'FALSE_POSITIVE') as false_positives,
                    COUNT(*) FILTER (WHERE verdict = 'UNDETERMINED') as undetermined
                FROM sessions
                WHERE source = 'SIEM' AND deleted_at IS NULL AND status != 'ARCHIVED'
                """
            )

            # Average completion duration (excluding active/waiting)
            avg_duration_sec = await conn.fetchval(
                """
                SELECT COALESCE(EXTRACT(EPOCH FROM AVG(completed_at - created_at)), 0)
                FROM sessions
                WHERE completed_at IS NOT NULL AND status IN ('COMPLETED', 'FAILED')
                AND deleted_at IS NULL AND status != 'ARCHIVED'
                """
            )

        return {
            "active_sessions": counts["active_sessions"] or 0,
            "pending_hitl": counts["pending_hitl"] or 0,
            "created_last_24h": counts["created_last_24h"] or 0,
            "completed_sessions": counts["completed_sessions"] or 0,
            "siem_sessions": counts["siem_sessions"] or 0,
            "user_sessions": counts["user_sessions"] or 0,
            "true_positives": verdicts["true_positives"] or 0,
            "false_positives": verdicts["false_positives"] or 0,
            "undetermined": verdicts["undetermined"] or 0,
            "avg_duration_seconds": float(avg_duration_sec),
        }

    async def register_agent_in_db(self, agent_id: str, config_path: str) -> None:
        """Upsert agent configuration path into agents registry table."""
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO agents (id, config_path)
                VALUES ($1, $2)
                ON CONFLICT (id) DO UPDATE SET config_path = EXCLUDED.config_path
                """,
                agent_id,
                config_path,
            )

    async def register_playbook_in_db(self, playbook_id: str, file_path: str) -> None:
        """Upsert playbook file path into playbooks registry table."""
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO playbooks (id, file_path)
                VALUES ($1, $2)
                ON CONFLICT (id) DO UPDATE SET file_path = EXCLUDED.file_path
                """,
                playbook_id,
                file_path,
            )

    async def map_agent_to_playbook(self, agent_id: str, playbook_id: str) -> None:
        """Create mapping relationship between an agent and a playbook."""
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO agent_playbooks (agent_id, playbook_id)
                VALUES ($1, $2)
                ON CONFLICT DO NOTHING
                """,
                agent_id,
                playbook_id,
            )

    async def get_allowed_playbooks_for_agent(self, agent_id: str) -> list[str]:
        """Get the list of playbook IDs mapped to the given agent ID."""
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT playbook_id FROM agent_playbooks WHERE agent_id = $1",
                agent_id,
            )
            return [row["playbook_id"] for row in rows]

    async def close(self) -> None:
        if self._pool:
            await self._pool.close()
            self._pool = None


# Singleton instance helper
postgres_session_repo = PostgresSessionRepository()

