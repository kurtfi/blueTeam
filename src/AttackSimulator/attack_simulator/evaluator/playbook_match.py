"""
Evaluates simulation runs by comparing expected vs actual playbook selections.
"""

import json
import uuid
from typing import Any
import structlog

from attack_simulator.models import db_repo

logger = structlog.get_logger(__name__)


async def get_expected_playbooks(mitre_ids: list[str]) -> list[str]:
    """
    Queries TriageCore's PlaybookRegistry to find matching playbooks for given MITRE IDs.
    """
    try:
        from triage_core.playbooks import registry as pb_registry
        candidates = pb_registry.find_for_alert(mitre_ids=mitre_ids)
        return [c.id for c in candidates]
    except Exception as e:
        logger.error("evaluator.playbook_registry_error", mitre_ids=mitre_ids, error=str(e))
        return []


async def check_actual_playbook(session_id: str) -> str | None:
    """
    Queries the session audit logs in PostgreSQL to find if and which playbook the agent triggered.
    """
    pool = await db_repo.get_pool()
    sess_uuid = uuid.UUID(session_id)
    
    async with pool.acquire() as conn:
        # Query for trigger_playbook tool calls in session_events
        rows = await conn.fetch(
            """
            SELECT metadata 
            FROM session_events 
            WHERE session_id = $1 
              AND event_type = 'tool_call'
              AND metadata->>'tool_name' = 'trigger_playbook'
            ORDER BY id DESC
            """,
            sess_uuid,
        )
        
        for row in rows:
            meta = row["metadata"]
            if isinstance(meta, str):
                try:
                    meta = json.loads(meta)
                except Exception:
                    continue
            
            tool_input = meta.get("tool_input", {})
            if isinstance(tool_input, str):
                try:
                    tool_input = json.loads(tool_input)
                except Exception:
                    pass
                    
            playbook_id = tool_input.get("playbook_id")
            if playbook_id:
                return str(playbook_id)
                
    return None


async def evaluate_run(run_id: str) -> dict[str, Any]:
    """
    Evaluates all results for a simulation run. Updates simulation_runs stats.
    """
    logger.info("evaluator.evaluating_run", run_id=run_id)
    results = await db_repo.get_run_results(run_id)
    
    matched_playbooks = 0
    mismatched_playbooks = 0
    no_playbook = 0
    sent_count = len(results)
    
    pool = await db_repo.get_pool()
    
    async with pool.acquire() as conn:
        for res in results:
            result_uuid = uuid.UUID(res["id"])
            session_id = res["session_id"]
            expected_mitre = res["expected_mitre"] or []
            
            if not session_id:
                # Webhook post failed, event never triggered
                await conn.execute(
                    "UPDATE simulation_results SET match_result = 'FAILED' WHERE id = $1",
                    result_uuid
                )
                mismatched_playbooks += 1
                continue
                
            # Get expected playbook list
            expected_list = await get_expected_playbooks(expected_mitre)
            expected_str = expected_list[0] if expected_list else None
            
            # Check actual playbook execution from postgres audits
            actual = await check_actual_playbook(session_id)
            
            # Check the status of the session to see if it has finished or is pending
            sess_row = await conn.fetchrow("SELECT status FROM sessions WHERE id = $1", uuid.UUID(session_id))
            sess_status = sess_row["status"] if sess_row else "FAILED"
            
            if sess_status in ("ACTIVE", "WAITING_APPROVAL") and actual is None:
                # If triage session is still active, mark as pending evaluation
                await conn.execute(
                    """
                    UPDATE simulation_results 
                    SET expected_playbook = $2, actual_playbook = $3, match_result = 'PENDING'
                    WHERE id = $1
                    """,
                    result_uuid,
                    expected_str,
                    None
                )
                continue

            # Determine verdict
            if actual:
                if actual in expected_list:
                    match_result = "CORRECT"
                    matched_playbooks += 1
                else:
                    match_result = "WRONG"
                    mismatched_playbooks += 1
            else:
                if not expected_list:
                    # No playbook was expected, and none was triggered -> CORRECT
                    match_result = "CORRECT"
                    matched_playbooks += 1
                else:
                    # Playbook was expected, but none triggered
                    match_result = "NO_PLAYBOOK"
                    no_playbook += 1
                    
            # Update the result record in PostgreSQL
            await conn.execute(
                """
                UPDATE simulation_results 
                SET expected_playbook = $2, actual_playbook = $3, match_result = $4
                WHERE id = $1
                """,
                result_uuid,
                expected_str,
                actual,
                match_result
            )
            
    # Update simulation_runs database statistics
    total_completed = matched_playbooks + mismatched_playbooks + no_playbook
    run_status = "COMPLETED" if total_completed >= sent_count else "RUNNING"
    
    await db_repo.update_run_stats(
        run_id=run_id,
        status=run_status,
        sent_events=sent_count,
        matched_playbooks=matched_playbooks,
        mismatched_playbooks=mismatched_playbooks,
        no_playbook=no_playbook
    )
    
    report = {
        "run_id": run_id,
        "status": run_status,
        "total_events": sent_count,
        "matched": matched_playbooks,
        "mismatched": mismatched_playbooks,
        "no_playbook": no_playbook,
        "accuracy_rate": (matched_playbooks / sent_count * 100.0) if sent_count > 0 else 0.0
    }
    
    logger.info("evaluator.run_evaluated", report=report)
    return report
