import asyncio
import json

import structlog

from agentic_common.memory import postgres_session_repo
from agentic_common.memory.redis_store import RedisSessionStore
from agentic_common.settings import settings
from agentix.agents.factory import AgentFactory
from agentix.core.react import StepType
from agentix.core.verdict import parse_verdict
from agentix.registry.catalog import ToolCatalog

logger = structlog.get_logger(__name__)

# Module-level reference — set by the API server at startup
_shared_catalog: ToolCatalog | None = None


def set_shared_catalog(catalog: ToolCatalog) -> None:
    """Called once at API startup to share the MCP-connected catalog."""
    global _shared_catalog
    _shared_catalog = catalog


async def process_siem_alert(session_id: str, payload: dict):
    """
    Initiates a SOC Triage agent session using the SOC Analyst agent
    and the shared MCP-connected ToolCatalog.
    """
    logger.info("triage_workflow.delay_startup", session_id=session_id, delay_seconds=15)
    await asyncio.sleep(15)

    logger.info("triage_workflow.start", session_id=session_id)

    catalog = _shared_catalog
    if catalog is None or len(catalog.all_tools()) == 0:
        logger.error(
            "triage_workflow.no_catalog",
            hint="Shared catalog is empty. Ensure set_shared_catalog() is called at startup.",
        )
        return

    # Convert payload into a prompt for the agent
    alert_details = json.dumps(payload, indent=2)

    # Create a comprehensive prompt for the agent to act as an Autonomous Tier 1 SOC Analyst
    prompt = f"""
You are an autonomous Tier 1 (T1) SOC Analyst. The following alert dropped from the SIEM:

ALERT DETAILS:
{alert_details}

YOUR TASK:
Analyze this alert, gather necessary context, distinguish between False Positive (FP) and True Positive (TP), and if necessary, contain the event and create a case.

CRITICAL INSTRUCTION FOR FINAL ANSWER:
Your "Final Answer" must explicitly include one of the following exact lines at the very end to indicate your verdict:
- VERDICT: TRUE_POSITIVE (if the alert is a confirmed security incident)
- VERDICT: FALSE_POSITIVE (if the alert is benign/false alarm/authorized activity)
- VERDICT: UNDETERMINED (if you cannot determine with the available information)

IMPORTANT ACTION RULES:
1. **Playbook-Driven Response**: First, use the `find_playbook_for_alert` with the incoming alert's rule.id or mitre.id to search for an appropriate playbook (e.g. PB-001, PB-003, PB-006 etc.).
2. Trigger the playbook you found with `trigger_playbook` and strictly follow its step-by-step instructions.
3. If you cannot find a suitable playbook, perform general analysis methods (IP/File reputation query, SIEM log review, Case Management case creation).

IMPORTANT NOTE (SIEM QUERIES):
- When using the `query_siem_logs` tool, you must adhere to the Lucene query string format.
- Field names and values must be separated by a colon (`:`) (never use `=`).
- Enclose the values to be queried in double quotes.
- Example Correct Queries:
  - `data.srcip:"10.10.10.99" AND data.dstuser:"admin"`
  - `rule.id:"5712"`
  - `rule.groups:authentication_failed`
- Incorrect queries containing equals (`=`) (e.g. `src_ip=10.10.10.99`) produce a 500 error on the SIEM Indexer side! Strictly avoid them.
"""
    redis_store = RedisSessionStore(redis_url=settings.redis_url)
    try:
        # Use the SOC Analyst agent with the shared catalog
        orchestrator = AgentFactory.create(
            "soc_analyst",
            catalog=catalog,
            memory=redis_store,
        )

        final_answer = None
        has_confirm = False
        async for step in orchestrator.run_stream(session_id=session_id, user_message=prompt):
            # Log the steps locally
            logger.info(
                "triage_workflow.step",
                session_id=session_id,
                step_type=step.step_type.value,
                content=step.content[:200] if step.content else "",
                tool=step.tool_name,
            )

            # Record event in PostgreSQL
            try:
                event_type = step.step_type.value
                actor = "agent" if step.step_type in (StepType.THINK, StepType.ACT, StepType.ANSWER) else "system"
                if step.step_type == StepType.CONFIRM:
                    event_type = "hitl_request"
                    actor = "agent"
                    has_confirm = True
                elif step.step_type == StepType.OBSERVE:
                    actor = "system" if "Teams Integration" in (step.content or "") else "tool"

                await postgres_session_repo.add_event(
                    session_id=session_id,
                    event_type=event_type,
                    actor=actor,
                    content=step.content,
                    metadata={
                        "tool_name": step.tool_name,
                        "tool_input": step.tool_input,
                        "tool_output": step.tool_output,
                    },
                )
            except Exception as ex:
                logger.critical(
                    "triage_workflow.event_log_failed",
                    session_id=session_id,
                    error=str(ex),
                    alert=True,
                    db_failure=True,
                )

            if step.step_type == StepType.ANSWER:
                final_answer = step.content

        if has_confirm:
            # Session is currently WAITING_APPROVAL, do not mark it COMPLETED yet.
            logger.info("triage_workflow.suspended_for_approval", session_id=session_id)
            return

        # Determine verdict from final answer
        verdict = parse_verdict(final_answer)

        await postgres_session_repo.update_status(
            session_id=session_id,
            status="COMPLETED",
            verdict=verdict,
        )

    except Exception as e:
        logger.exception("triage_workflow.error", session_id=session_id, error=str(e))
        # Update status to FAILED in Postgres
        try:
            await postgres_session_repo.update_status(
                session_id=session_id,
                status="FAILED",
            )
            await postgres_session_repo.add_event(
                session_id=session_id,
                event_type="error",
                actor="system",
                content=f"Workflow failed with error: {str(e)}",
            )
        except Exception as db_ex:
            logger.critical(
                "triage_workflow.db_fail_log_failed",
                session_id=session_id,
                error=str(db_ex),
                alert=True,
                db_failure=True,
            )
    finally:
        if hasattr(redis_store, "close"):
            await redis_store.close()


# Maintain backwards compatibility / alias for webhook router
process_wazuh_alert = process_siem_alert
