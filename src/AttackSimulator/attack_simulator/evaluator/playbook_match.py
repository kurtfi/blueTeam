"""
Evaluates simulation runs by comparing expected vs actual playbook selections.
"""

import json
import re
import uuid
from typing import Any

import structlog
from attack_simulator.evaluator.agentix_gateway import AgentixSessionGateway
from attack_simulator.evaluator.gateway import PlaybookRegistryGateway
from attack_simulator.repository import db_repo

logger = structlog.get_logger(__name__)

gateway = PlaybookRegistryGateway()
agentix_gateway = AgentixSessionGateway()

# In-memory lookup cache to prevent redundant scans
_expected_playbooks_cache: dict[tuple[str, ...], list[str]] = {}


async def get_expected_playbooks(mitre_ids: list[str]) -> list[str]:
    """
    Queries TriageCore's PlaybookRegistry via gateway to find matching playbooks for given MITRE IDs.
    Sorted by specificity first, then severity.
    """
    if not mitre_ids:
        return []

    mitre_tuple = tuple(sorted(mitre_ids))
    if mitre_tuple in _expected_playbooks_cache:
        return _expected_playbooks_cache[mitre_tuple]

    try:
        candidates = gateway.find_playbooks_for_mitre(mitre_ids)

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

        def specificity_score(pb) -> int:
            score = 99
            for pb_mid in pb.mitre_ids:
                for mid in mitre_ids:
                    pbm = pb_mid.upper().strip()
                    m = mid.upper().strip()
                    if pbm == m:
                        score = min(score, 1)  # Exact match
                    elif m.startswith(pbm + "."):
                        score = min(score, 2)  # Parent match
                    elif pbm.startswith(m + "."):
                        score = min(score, 3)  # Child match
                    elif pbm.startswith(m) or m.startswith(pbm):
                        score = min(score, 4)  # General prefix/suffix
            return score

        candidates_sorted = sorted(
            candidates, key=lambda p: (specificity_score(p), severity_order.get(p.severity.value, 9), p.id)
        )
        result = [c.id for c in candidates_sorted]
        _expected_playbooks_cache[mitre_tuple] = result
        return result
    except Exception as e:
        logger.error("evaluator.playbook_registry_error", mitre_ids=mitre_ids, error=str(e))
        return []


def extract_playbook_from_metadata(meta: Any) -> tuple[str | None, str | None]:
    """
    Parses metadata dictionary/JSON to extract triggered and detailed playbooks.
    Returns a tuple (triggered_playbook, detailed_playbook).
    """
    if isinstance(meta, str):
        try:
            meta = json.loads(meta)
        except Exception:
            meta = None

    if not (meta and isinstance(meta, dict)):
        return None, None

    tool_name = meta.get("tool_name")
    tool_input = meta.get("tool_input") or {}
    if isinstance(tool_input, str):
        try:
            tool_input = json.loads(tool_input)
        except Exception:
            pass

    if not isinstance(tool_input, dict):
        return None, None

    pb = tool_input.get("playbook_id")
    if pb:
        pb_str = str(pb)
        if tool_name == "trigger_playbook":
            return pb_str, None
        elif tool_name == "get_playbook_details":
            return None, pb_str

    return None, None


def extract_playbooks_from_text(content: str) -> list[str]:
    """
    Finds all patterns of PB-XXX (e.g. PB-001) in the content.
    """
    return re.findall(r"PB-\d{3}", content)


def determine_session_verdict(actual: str | None, expected_list: list[str], sess_status: str) -> str:
    """
    Pure function to determine the verdict of a session based on expected playbooks,
    actual playbook triggered, and session status.
    """
    if sess_status in ("ACTIVE", "WAITING_APPROVAL") and actual is None:
        return "PENDING"

    if actual:
        return "CORRECT" if actual in expected_list else "WRONG"

    return "CORRECT" if not expected_list else "NO_PLAYBOOK"


async def check_actual_playbook(session_id: str, conn: Any | None = None) -> str | None:
    """
    Queries the session audit logs via HTTP gateway to find if and which playbook the agent triggered,
    detailed, or referenced in its final answer.
    """
    rows = await agentix_gateway.get_session_events(session_id)

    triggered_pbs = []
    detailed_pbs = []
    answer_pbs = []

    for row in rows:
        ev_type = row["event_type"]
        actor = row["actor"]
        content = row["content"] or ""
        meta = row["metadata"]

        triggered_pb, detailed_pb = extract_playbook_from_metadata(meta)
        if triggered_pb:
            triggered_pbs.append(triggered_pb)
        if detailed_pb:
            detailed_pbs.append(detailed_pb)

        if ev_type == "answer" and actor == "agent":
            for m in extract_playbooks_from_text(content):
                if m not in answer_pbs:
                    answer_pbs.append(m)

    # Priority mapping:
    # 1. Any playbook explicitly triggered
    if triggered_pbs:
        return triggered_pbs[-1]

    # 2. Any playbook mentioned in final answer
    if answer_pbs:
        return answer_pbs[0]

    # 3. Any playbook details requested
    if detailed_pbs:
        return detailed_pbs[-1]

    return None


async def evaluate_run(run_id: str) -> dict[str, Any]:
    """
    Evaluates all results for a simulation run. Updates simulation_runs stats.
    Evaluates on a session level rather than event level.
    """
    logger.info("evaluator.evaluating_run", run_id=run_id)
    results = await db_repo.get_run_results(run_id)

    # Group results by session_id
    sessions_map: dict[str, list[dict[str, Any]]] = {}
    no_session_results: list[dict[str, Any]] = []

    for res in results:
        sess_id = res.get("session_id")
        if sess_id:
            sessions_map.setdefault(sess_id, []).append(res)
        else:
            no_session_results.append(res)

    matched_playbooks = 0
    mismatched_playbooks = 0
    no_playbook = 0

    pool = await db_repo.get_pool()

    # We will accumulate database updates: (result_id, expected_pb, actual_pb, match_result)
    db_updates: list[tuple[uuid.UUID, str | None, str | None, str]] = []

    # 1. Process results that have a session
    for session_id, res_list in sessions_map.items():
        # Get expected playbooks for the union of all MITRE techniques in this session
        all_mitre_ids: list[str] = []
        for r in res_list:
            expected_mitre = r.get("expected_mitre") or []
            all_mitre_ids.extend(expected_mitre)
        all_mitre_ids = list(set(all_mitre_ids))

        expected_list = await get_expected_playbooks(all_mitre_ids)
        expected_str = ", ".join(expected_list) if expected_list else None

        # Check actual playbook and status for the session
        actual = await check_actual_playbook(session_id)
        sess_status = await agentix_gateway.get_session_status(session_id)

        if not sess_status:
            sess_status = "FAILED"

        match_result = determine_session_verdict(actual, expected_list, sess_status)

        # Count the session verdict (pending is not counted yet, keeping the run in RUNNING status)
        if match_result == "CORRECT":
            matched_playbooks += 1
        elif match_result in ("WRONG", "FAILED"):
            mismatched_playbooks += 1
        elif match_result == "NO_PLAYBOOK":
            no_playbook += 1

        # Add updates for all events in this session
        for r in res_list:
            db_updates.append((uuid.UUID(r["id"]), expected_str, actual, match_result))

    # 2. Process results that failed to create a session (unsent/failed events)
    for r in no_session_results:
        # Each unsent event counts as a separate failed attempt
        expected_mitre = r.get("expected_mitre") or []
        expected_list = await get_expected_playbooks(expected_mitre)
        expected_str = ", ".join(expected_list) if expected_list else None

        match_result = "FAILED"
        mismatched_playbooks += 1

        db_updates.append((uuid.UUID(r["id"]), expected_str, None, match_result))

    # Apply updates in a single transaction
    async with pool.acquire() as conn:
        async with conn.transaction():
            for res_uuid, expected_pb, actual_pb, match_result in db_updates:
                await conn.execute(
                    """
                    UPDATE simulator.simulation_results 
                    SET expected_playbook = $2, actual_playbook = $3, match_result = $4
                    WHERE id = $1
                    """,
                    res_uuid,
                    expected_pb,
                    actual_pb,
                    match_result,
                )

    # Update simulation_runs database statistics
    total_completed = matched_playbooks + mismatched_playbooks + no_playbook
    total_sessions_count = len(sessions_map) + len(no_session_results)

    # Run status is COMPLETED when all sessions are finalized
    run_status = "COMPLETED" if total_completed >= total_sessions_count else "RUNNING"

    await db_repo.update_run_stats(
        run_id=run_id,
        status=run_status,
        sent_events=len(results),
        matched_playbooks=matched_playbooks,
        mismatched_playbooks=mismatched_playbooks,
        no_playbook=no_playbook,
    )

    accuracy_rate = (matched_playbooks / total_sessions_count * 100.0) if total_sessions_count > 0 else 0.0

    report = {
        "run_id": run_id,
        "status": run_status,
        "total_events": len(results),
        "matched": matched_playbooks,
        "mismatched": mismatched_playbooks,
        "no_playbook": no_playbook,
        "accuracy_rate": round(accuracy_rate, 1),
    }

    logger.info("evaluator.run_evaluated", report=report)
    return report

