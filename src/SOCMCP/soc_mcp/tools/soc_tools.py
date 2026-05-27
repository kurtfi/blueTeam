import os
import json
import structlog
from soc_mcp.tools import mcp
from soc_mcp.integrations.registry import registry

logger = structlog.get_logger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Playbook Tools
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
async def trigger_playbook(
    playbook_id: str,
    agent_id: str = "",
    agent_name: str = "",
    src_ip: str = "",
    rule_id: str = "",
    mitre_ids: list[str] = None,
    extra_context: dict = None,
) -> str:
    """
    Triggers the specified SOC playbook and returns step-by-step response
    instructions for the SOC agent. Each step specifies which tool to use
    and which steps require human approval.
    """
    logger.info(
        "tool.trigger_playbook",
        playbook_id=playbook_id,
        agent_id=agent_id,
        src_ip=src_ip,
    )
    try:
        from soc_mcp.playbooks import registry as pb_registry
        from soc_mcp.playbooks.base import PlaybookContext

        ctx = PlaybookContext(
            alert={
                "agent_id": agent_id,
                "agent_name": agent_name,
                "src_ip": src_ip,
                "rule_id": rule_id,
                "mitre_ids": mitre_ids or [],
                **(extra_context or {}),
            }
        )
        result = pb_registry.trigger(playbook_id, ctx)
        return result.instructions

    except KeyError as e:
        try:
            from soc_mcp.playbooks import registry as pb_registry
            available = ", ".join(p["id"] for p in pb_registry.list_all())
            return f"Playbook not found: {e}\nAvailable playbooks: {available}"
        except Exception:
            return f"Playbook not found: {e}"
    except Exception as e:
        logger.error("playbook.trigger.error", error=str(e))
        return f"Error triggering playbook: {str(e)}"


@mcp.tool()
async def list_playbooks(filter_mitre: str = "", filter_severity: str = "") -> str:
    """Lists all registered SOC playbooks."""
    logger.info("tool.list_playbooks", filter_mitre=filter_mitre, filter_severity=filter_severity)
    try:
        from soc_mcp.playbooks import registry as pb_registry
        playbooks = pb_registry.list_all()

        if filter_mitre:
            playbooks = [
                p for p in playbooks
                if any(filter_mitre.upper() in mid.upper() for mid in p["mitre_ids"])
            ]
        if filter_severity:
            playbooks = [p for p in playbooks if p["severity"] == filter_severity.lower()]

        if not playbooks:
            return "No playbook matches the filter."

        lines = ["# Available SOC Playbooks\n"]
        for pb in playbooks:
            lines.append(
                f"**{pb['id']}** – {pb['name']}\n"
                f"  MITRE: {', '.join(pb['mitre_ids'])} | "
                f"Severity: {pb['severity'].upper()} | "
                f"Step: {pb['steps']}\n"
            )
        return "\n".join(lines)
    except Exception as e:
        logger.error("playbook.list.error", error=str(e))
        return f"Error fetching playbook list: {str(e)}"


@mcp.tool()
async def find_playbook_for_alert(
    rule_id: str = "",
    mitre_ids: list[str] = None,
) -> str:
    """Finds the most suitable playbook for a given rule ID or MITRE technique IDs."""
    logger.info("tool.find_playbook_for_alert", rule_id=rule_id, mitre_ids=mitre_ids)
    try:
        from soc_mcp.playbooks import registry as pb_registry
        candidates = pb_registry.find_for_alert(rule_id=rule_id, mitre_ids=mitre_ids or [])

        if not candidates:
            return (
                f"No suitable playbook found for Rule ID '{rule_id}' or MITRE {mitre_ids}.\n"
                f"Use the list_playbooks tool to see all playbooks."
            )

        lines = [f"Suitable playbooks ({len(candidates)} found):\n"]
        for pb in candidates:
            lines.append(
                f"  → **{pb.id}**: {pb.name} "
                f"[{pb.severity.value.upper()}] "
                f"MITRE: {', '.join(pb.mitre_ids)}"
            )
        lines.append(
            f"\nTo trigger the playbook: "
            f"trigger_playbook(playbook_id='{candidates[0].id}', ...)"
        )
        return "\n".join(lines)
    except Exception as e:
        logger.error("playbook.find.error", error=str(e))
        return f"Playbook search error: {str(e)}"

# ─────────────────────────────────────────────────────────────────────────────
# Case Management Tools
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
async def create_case(title: str = "", description: str = "", severity: int = 2, tags: list[str] = None) -> str:
    """Creates a new case on SOAR/Case Management.
    Returns a message containing 'Case ID: <id>' on success.
    IMPORTANT: Save the returned Case ID (e.g. ~12345) — you will need it for add_case_note and update_case_status.
    """
    provider = registry.get_case_management_provider()
    return await provider.create_case(title, description, severity, tags)

@mcp.tool()
async def add_case_note(case_id: str, note: str, task_title: str = "Investigation Note") -> str:
    """Adds a note/task to an existing case.
    IMPORTANT: You MUST first create a case using 'create_case' and use the exact Case ID returned (e.g. ~12345).
    Do NOT use 'N/A', 'UNKNOWN', or any placeholder — only the real Case ID from create_case output.
    """
    provider = registry.get_case_management_provider()
    return await provider.add_case_note(case_id, note, task_title)

@mcp.tool()
async def update_case_status(case_id: str, status: str, resolution_type: str = "TruePositive", summary: str = "") -> str:
    """Updates the status of an existing case.
    IMPORTANT: You MUST first create a case using 'create_case' and use the exact Case ID returned (e.g. ~12345).
    Valid status values: FalsePositive, TruePositive, Indeterminate, InProgress, New, Duplicated, Other.
    Common mappings: use 'FalsePositive' for benign/false alarms, 'TruePositive' for confirmed threats,
    'InProgress' for ongoing investigation, 'Indeterminate' when uncertain.
    The resolution_type is used as a hint when status maps to a resolution (e.g. 'FalsePositive', 'TruePositive').
    """
    provider = registry.get_case_management_provider()
    return await provider.update_case_status(case_id, status, resolution_type, summary)

@mcp.tool()
async def create_alert(title: str = "", description: str = "", source: str = "Agentix", source_ref: str = "", severity: int = 2, tags: list[str] = None, observables: list[dict] = None) -> str:
    """Creates an alert for triage in the Case Management system."""
    provider = registry.get_case_management_provider()
    return await provider.create_alert(title, description, source, source_ref, severity, tags, observables)

# ─────────────────────────────────────────────────────────────────────────────
# Enrichment Tools
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
async def get_ip_reputation(ip_address: str) -> str:
    """Queries IP address reputation."""
    provider = registry.get_enrichment_provider()
    return await provider.get_ip_reputation(ip_address)

@mcp.tool()
async def get_file_reputation(file_hash: str) -> str:
    """Queries file hash reputation."""
    provider = registry.get_enrichment_provider()
    return await provider.get_file_reputation(file_hash)

@mcp.tool()
async def get_domain_url_reputation(url_or_domain: str) -> str:
    """Queries domain or URL reputation."""
    provider = registry.get_enrichment_provider()
    return await provider.get_domain_url_reputation(url_or_domain)

# ─────────────────────────────────────────────────────────────────────────────
# IAM / AD Tools
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
async def get_ad_user_info(username: str) -> str:
    """Fetches user information via IAM/AD."""
    provider = registry.get_iam_provider()
    return await provider.get_user_info(username)

@mcp.tool()
async def disable_user_account(username: str) -> str:
    """Disables a compromised user account."""
    provider = registry.get_iam_provider()
    return await provider.disable_user_account(username)

# ─────────────────────────────────────────────────────────────────────────────
# SIEM Tools
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
async def query_siem_logs(query: str, time_range: str = "last 1 hour") -> str:
    """Fetches logs by running a query on the SIEM."""
    provider = registry.get_siem_provider()
    return await provider.query_logs(query, time_range)

# ─────────────────────────────────────────────────────────────────────────────
# Endpoint & Containment Tools
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
async def get_endpoint_info(agent_id: str) -> str:
    """Fetches endpoint information (hostname, IP, OS)."""
    provider = registry.get_endpoint_provider()
    return await provider.get_endpoint_info(agent_id)

@mcp.tool()
async def isolate_endpoint(agent_id: str) -> str:
    """Isolates the endpoint from the network after detecting malicious activity."""
    provider = registry.get_endpoint_provider()
    return await provider.isolate_endpoint(agent_id)

@mcp.tool()
async def block_ip(ip_address: str) -> str:
    """Blocks malicious IP on the firewall."""
    provider = registry.get_firewall_provider()
    return await provider.block_ip(ip_address)

# ─────────────────────────────────────────────────────────────────────────────
# SOAR Tools
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
async def trigger_soar_workflow(workflow_id: str, data: dict = None, webhook_url: str = "") -> str:
    """Triggers a workflow on SOAR."""
    provider = registry.get_soar_provider()
    return await provider.trigger_workflow(workflow_id, data, webhook_url)
