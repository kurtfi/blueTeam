"""
PostgreSQL models and repository interface for AttackSimulator.
"""

import json
import uuid
from datetime import datetime
from typing import Any

import asyncpg  # type: ignore[import-untyped]
import structlog

from attack_simulator.config import DATABASE_URL

logger = structlog.get_logger(__name__)


class DatabaseRepository:
    """
    Data access layer for simulator scenarios, events, runs, and results.
    """

    def __init__(self, pool: asyncpg.Pool | None = None) -> None:
        self._pool = pool

    async def get_pool(self) -> asyncpg.Pool:
        if self._pool is None:
            self._pool = await asyncpg.create_pool(dsn=DATABASE_URL)
        return self._pool

    async def create_scenario(
        self,
        name: str,
        description: str | None,
        mitre_ids: list[str],
        source_dataset: str,
        source_path: str,
        total_events: int = 0,
        status: str = "passive",
    ) -> str:
        # Truncate strings to prevent database length constraint issues
        name = name[:255]
        if description:
            description = description[:1000]
        source_dataset = source_dataset[:100]
        source_path = source_path[:1000]
        status = status[:20]

        pool = await self.get_pool()
        scenario_id = uuid.uuid4()

        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO attack_scenarios (
                    id, name, description, mitre_ids, source_dataset, source_path, total_events, status, created_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
                """,
                scenario_id,
                name,
                description,
                mitre_ids,
                source_dataset,
                source_path,
                total_events,
                status,
            )
        logger.info("db.scenario_created", scenario_id=str(scenario_id), name=name, status=status)
        return str(scenario_id)

    async def get_scenario_by_name(self, name: str) -> dict[str, Any] | None:
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM attack_scenarios WHERE name = $1", name
            )
            if row:
                d = dict(row)
                d["id"] = str(d["id"])
                return d
        return None

    async def get_scenario_by_path(self, source_path: str) -> dict[str, Any] | None:
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM attack_scenarios WHERE source_path = $1", source_path
            )
            if row:
                d = dict(row)
                d["id"] = str(d["id"])
                return d
        return None

    async def activate_scenario(self, scenario_id: str) -> None:
        """
        Sets the target scenario to active, and sets all other scenarios to passive.
        Also synchronizes the attack_events status values.
        """
        pool = await self.get_pool()
        sc_uuid = uuid.UUID(scenario_id)
        async with pool.acquire() as conn:
            async with conn.transaction():
                # 1. Reset all to passive
                await conn.execute("UPDATE attack_scenarios SET status = 'passive'")
                await conn.execute("UPDATE attack_events SET status = 'passive'")
                # 2. Activate target scenario
                await conn.execute("UPDATE attack_scenarios SET status = 'active' WHERE id = $1", sc_uuid)
                # 3. Activate target events
                await conn.execute("UPDATE attack_events SET status = 'active' WHERE scenario_id = $1", sc_uuid)
        logger.info("db.scenario_activated", scenario_id=scenario_id)

    async def list_scenarios(self) -> list[dict[str, Any]]:
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("SELECT * FROM attack_scenarios ORDER BY created_at DESC")
            results = []
            for row in rows:
                d = dict(row)
                d["id"] = str(d["id"])
                results.append(d)
            return results

    async def delete_scenario(self, scenario_id: str) -> None:
        pool = await self.get_pool()
        sc_uuid = uuid.UUID(scenario_id)
        async with pool.acquire() as conn:
            await conn.execute("DELETE FROM attack_scenarios WHERE id = $1", sc_uuid)
        logger.info("db.scenario_deleted", scenario_id=scenario_id)

    async def insert_attack_events(self, events: list[dict[str, Any]], status: str = "passive") -> None:
        """
        Inserts a batch of attack events.
        """
        if not events:
            return

        from attack_simulator.mapper.wazuh_template import strip_information_leakage

        pool = await self.get_pool()
        async with pool.acquire() as conn:
            async with conn.transaction():
                for ev in events:
                    clean_alert = strip_information_leakage(ev["wazuh_alert"], ev["mitre_technique"])
                    wazuh_alert_str = json.dumps(clean_alert)
                    sc_uuid = uuid.UUID(ev["scenario_id"])
                    
                    # Truncate string inputs to fit VARCHAR limits
                    mitre_technique = ev["mitre_technique"][:255]
                    mitre_tactic = ev["mitre_tactic"][:255] if ev.get("mitre_tactic") else None
                    correlation_type = ev["correlation_type"][:255] if ev.get("correlation_type") else "direct"
                    correlation_rule = ev["correlation_rule"][:1000] if ev.get("correlation_rule") else None
                    raw_log_hash = ev["raw_log_hash"][:255] if ev.get("raw_log_hash") else None
                    status_val = status[:20]

                    await conn.execute(
                        """
                        INSERT INTO attack_events (
                            scenario_id, sequence_order, mitre_technique, mitre_tactic,
                            correlation_type, raw_event_count, correlation_rule,
                            wazuh_alert, raw_log_hash, status, created_at
                        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
                        """,
                        sc_uuid,
                        ev["sequence_order"],
                        mitre_technique,
                        mitre_tactic,
                        correlation_type,
                        ev["raw_event_count"],
                        correlation_rule,
                        wazuh_alert_str,
                        raw_log_hash,
                        status_val,
                    )

    async def get_scenario_events(self, scenario_id: str) -> list[dict[str, Any]]:
        pool = await self.get_pool()
        sc_uuid = uuid.UUID(scenario_id)
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM attack_events WHERE scenario_id = $1 ORDER BY sequence_order ASC",
                sc_uuid,
            )
            results = []
            for row in rows:
                d = dict(row)
                d["id"] = str(d["id"])
                d["scenario_id"] = str(d["scenario_id"])
                # Parse JSON wazuh_alert
                if isinstance(d["wazuh_alert"], str):
                    d["wazuh_alert"] = json.loads(d["wazuh_alert"])
                results.append(d)
            return results

    async def create_run(self, scenario_id: str, total_events: int, send_rate_per_sec: float, bulk_run_id: str | None = None) -> str:
        pool = await self.get_pool()
        sc_uuid = uuid.UUID(scenario_id)
        run_id = uuid.uuid4()
        bulk_uuid = uuid.UUID(bulk_run_id) if bulk_run_id else None

        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO simulation_runs (
                    id, scenario_id, status, total_events, sent_events, send_rate_per_sec, bulk_run_id, started_at, created_at
                ) VALUES ($1, $2, 'RUNNING', $3, 0, $4, $5, NOW(), NOW())
                """,
                run_id,
                sc_uuid,
                total_events,
                send_rate_per_sec,
                bulk_uuid,
            )
        logger.info("db.run_created", run_id=str(run_id), scenario_id=scenario_id, bulk_run_id=bulk_run_id)
        return str(run_id)

    async def update_run_stats(
        self,
        run_id: str,
        status: str,
        sent_events: int,
        matched_playbooks: int = 0,
        mismatched_playbooks: int = 0,
        no_playbook: int = 0,
    ) -> None:
        pool = await self.get_pool()
        run_uuid = uuid.UUID(run_id)
        status = status[:50]
        completed_at = datetime.now() if status in ("COMPLETED", "FAILED") else None

        async with pool.acquire() as conn:
            if completed_at:
                await conn.execute(
                    """
                    UPDATE simulation_runs 
                    SET status = $2, sent_events = $3, matched_playbooks = $4,
                        mismatched_playbooks = $5, no_playbook = $6, completed_at = $7
                    WHERE id = $1
                    """,
                    run_uuid,
                    status,
                    sent_events,
                    matched_playbooks,
                    mismatched_playbooks,
                    no_playbook,
                    completed_at,
                )
            else:
                await conn.execute(
                    """
                    UPDATE simulation_runs 
                    SET status = $2, sent_events = $3, matched_playbooks = $4,
                        mismatched_playbooks = $5, no_playbook = $6
                    WHERE id = $1
                    """,
                    run_uuid,
                    status,
                    sent_events,
                    matched_playbooks,
                    mismatched_playbooks,
                    no_playbook,
                )

    async def get_run(self, run_id: str) -> dict[str, Any] | None:
        pool = await self.get_pool()
        run_uuid = uuid.UUID(run_id)
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM simulation_runs WHERE id = $1", run_uuid
            )
            if row:
                d = dict(row)
                d["id"] = str(d["id"])
                if d.get("scenario_id"):
                    d["scenario_id"] = str(d["scenario_id"])
                return d
        return None

    async def get_latest_runs(self, limit: int = 10) -> list[dict[str, Any]]:
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT r.*, s.name as scenario_name 
                FROM simulation_runs r 
                LEFT JOIN attack_scenarios s ON r.scenario_id = s.id 
                ORDER BY r.created_at DESC LIMIT $1
                """,
                limit,
            )
            results = []
            for row in rows:
                d = dict(row)
                d["id"] = str(d["id"])
                if d.get("scenario_id"):
                    d["scenario_id"] = str(d["scenario_id"])
                results.append(d)
            return results

    async def insert_simulation_result(
        self,
        run_id: str,
        event_id: str,
        session_id: str | None,
        expected_mitre: list[str],
        expected_playbook: str | None,
        actual_playbook: str | None = None,
        match_result: str = "PENDING",
        response_time_ms: int | None = None,
    ) -> str:
        # Truncate strings to prevent database length constraint issues
        if session_id:
            session_id = session_id[:255]
        if actual_playbook:
            actual_playbook = actual_playbook[:255]
        if expected_playbook:
            expected_playbook = expected_playbook[:255]
        match_result = match_result[:100]

        pool = await self.get_pool()
        run_uuid = uuid.UUID(run_id)
        ev_uuid = uuid.UUID(event_id)
        result_id = uuid.uuid4()

        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO simulation_results (
                    id, run_id, event_id, session_id, expected_mitre, expected_playbook,
                    actual_playbook, match_result, response_time_ms, created_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
                """,
                result_id,
                run_uuid,
                ev_uuid,
                session_id,
                expected_mitre,
                expected_playbook,
                actual_playbook,
                match_result,
                response_time_ms,
            )
        return str(result_id)

    async def get_run_results(self, run_id: str) -> list[dict[str, Any]]:
        pool = await self.get_pool()
        run_uuid = uuid.UUID(run_id)
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT res.*, ev.mitre_technique, ev.sequence_order
                FROM simulation_results res
                JOIN attack_events ev ON res.event_id = ev.id
                WHERE res.run_id = $1
                ORDER BY ev.sequence_order ASC
                """,
                run_uuid,
            )
            results = []
            for row in rows:
                d = dict(row)
                d["id"] = str(d["id"])
                d["run_id"] = str(d["run_id"])
                d["event_id"] = str(d["event_id"])
                results.append(d)
            return results

    async def get_agentix_session(self, session_id: str) -> dict[str, Any] | None:
        """
        Reads from Agentix's core sessions table to check runtime playbook execution details.
        """
        pool = await self.get_pool()
        sess_uuid = uuid.UUID(session_id)
        async with pool.acquire() as conn:
            # We query Agentix's sessions table (created in 001_create_sessions.sql)
            row = await conn.fetchrow(
                "SELECT * FROM sessions WHERE id = $1",
                sess_uuid,
            )
            if row:
                d = dict(row)
                d["id"] = str(d["id"])
                return d
        return None

    async def create_bulk_run(
        self,
        name: str,
        llm_provider: str | None,
        llm_model: str | None,
        strip_labels: bool,
        send_rate_per_sec: float,
        total_scenarios: int,
    ) -> str:
        pool = await self.get_pool()
        bulk_uuid = uuid.uuid4()
        name = name[:255]
        if llm_provider:
            llm_provider = llm_provider[:50]
        if llm_model:
            llm_model = llm_model[:255]

        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO simulation_bulk_runs (
                    id, name, llm_provider, llm_model, strip_labels, send_rate_per_sec,
                    status, total_scenarios, completed_scenarios, matched_playbooks,
                    mismatched_playbooks, no_playbook, created_at
                ) VALUES ($1, $2, $3, $4, $5, $6, 'RUNNING', $7, 0, 0, 0, 0, NOW())
                """,
                bulk_uuid,
                name,
                llm_provider,
                llm_model,
                strip_labels,
                send_rate_per_sec,
                total_scenarios,
            )
        logger.info("db.bulk_run_created", bulk_run_id=str(bulk_uuid), name=name)
        return str(bulk_uuid)

    async def get_bulk_runs(self, limit: int = 20) -> list[dict[str, Any]]:
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM simulation_bulk_runs ORDER BY created_at DESC LIMIT $1",
                limit,
            )
            results = []
            for row in rows:
                d = dict(row)
                d["id"] = str(d["id"])
                results.append(d)
            return results

    async def get_bulk_run(self, bulk_run_id: str) -> dict[str, Any] | None:
        pool = await self.get_pool()
        bulk_uuid = uuid.UUID(bulk_run_id)
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM simulation_bulk_runs WHERE id = $1",
                bulk_uuid,
            )
            if row:
                d = dict(row)
                d["id"] = str(d["id"])
                return d
        return None

    async def update_bulk_run_stats(
        self,
        bulk_run_id: str,
        status: str,
        completed_scenarios: int,
        matched: int,
        mismatched: int,
        nobook: int,
    ) -> None:
        pool = await self.get_pool()
        bulk_uuid = uuid.UUID(bulk_run_id)
        status = status[:50]
        completed_at = datetime.now() if status in ("COMPLETED", "FAILED", "CANCELLED", "PARTIALLY_COMPLETED") else None

        async with pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE simulation_bulk_runs
                SET status = $2, completed_scenarios = $3, matched_playbooks = $4,
                    mismatched_playbooks = $5, no_playbook = $6, completed_at = $7
                WHERE id = $1
                """,
                bulk_uuid,
                status,
                completed_scenarios,
                matched,
                mismatched,
                nobook,
                completed_at,
            )
        logger.info("db.bulk_run_updated", bulk_run_id=bulk_run_id, status=status)

    async def cancel_bulk_run(self, bulk_run_id: str) -> None:
        """
        Cancels a bulk run by setting its status to CANCELLED (or PARTIALLY_COMPLETED
        if some scenarios are already done) and computing statistics up to the point of cancellation.
        """
        pool = await self.get_pool()
        bulk_uuid = uuid.UUID(bulk_run_id)
        async with pool.acquire() as conn:
            # Fetch current sub-run statistics
            runs = await self.get_runs_for_bulk(bulk_run_id)
            completed_scenarios = 0
            matched = 0
            mismatched = 0
            nobook = 0
            for r in runs:
                if r["status"] in ("COMPLETED", "FAILED"):
                    completed_scenarios += 1
                    matched += r.get("matched_playbooks", 0)
                    mismatched += r.get("mismatched_playbooks", 0)
                    nobook += r.get("no_playbook", 0)

            final_status = "PARTIALLY_COMPLETED" if completed_scenarios > 0 else "CANCELLED"

            await conn.execute(
                """
                UPDATE simulation_bulk_runs
                SET status = $2, completed_scenarios = $3, matched_playbooks = $4,
                    mismatched_playbooks = $5, no_playbook = $6, completed_at = NOW()
                WHERE id = $1 AND status = 'RUNNING'
                """,
                bulk_uuid,
                final_status,
                completed_scenarios,
                matched,
                mismatched,
                nobook,
            )
        logger.info("db.bulk_run_cancelled", bulk_run_id=bulk_run_id, final_status=final_status)

    async def get_runs_for_bulk(self, bulk_run_id: str) -> list[dict[str, Any]]:
        pool = await self.get_pool()
        bulk_uuid = uuid.UUID(bulk_run_id)
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT r.*, s.name as scenario_name
                FROM simulation_runs r
                LEFT JOIN attack_scenarios s ON r.scenario_id = s.id
                WHERE r.bulk_run_id = $1
                ORDER BY r.created_at ASC
                """,
                bulk_uuid,
            )
            results = []
            for row in rows:
                d = dict(row)
                d["id"] = str(d["id"])
                d["scenario_id"] = str(d["scenario_id"]) if d.get("scenario_id") else None
                d["bulk_run_id"] = str(d["bulk_run_id"]) if d.get("bulk_run_id") else None
                results.append(d)
            return results

    async def close(self) -> None:
        if self._pool:
            await self._pool.close()
            self._pool = None


# Singleton helper instance
db_repo = DatabaseRepository()
