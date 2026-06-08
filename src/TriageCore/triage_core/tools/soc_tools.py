from typing import Any

import structlog

from triage_core.integrations.registry import registry
from triage_core.tools import mcp

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
    mitre_ids: list[str] | None = None,
    extra_context: dict[str, Any] | None = None,
) -> str:
    """
    Triggers the specified SOC playbook and returns a JSON object with:
    - ``instructions``: Full step-by-step markdown for the SOC agent to follow.
    - ``playbook_id``, ``playbook_name``, ``mitre_ids``, ``severity``: Playbook metadata.
    - ``steps_count``: Total number of response steps.
    - ``approval_required_steps``: List of step titles that require human approval before execution.
    - ``case_template``: TheHive case template name (if configured).
    - ``soar_workflow_id``: SOAR workflow to trigger (if configured).
    """
    logger.info(
        "tool.trigger_playbook",
        playbook_id=playbook_id,
        agent_id=agent_id,
        src_ip=src_ip,
    )

    # Validate extra_context: keys must be str, values must be JSON-safe primitives
    _ALLOWED_TYPES = (str, int, float, bool, list, dict, type(None))
    if extra_context is not None:
        if not isinstance(extra_context, dict):
            return "Invalid extra_context: must be a dict (key-value pairs)."
        for k, v in extra_context.items():
            if not isinstance(k, str):
                return f"Invalid extra_context: key {k!r} must be a string."
            if not isinstance(v, _ALLOWED_TYPES):
                return (
                    f"Invalid extra_context: value for key '{k}' has unsupported type "
                    f"'{type(v).__name__}'. Allowed: str, int, float, bool, list, dict, null."
                )

    try:
        from triage_core.playbooks import registry as pb_registry
        from triage_core.playbooks.base import PlaybookContext

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
        import json

        return json.dumps(result.to_dict(), ensure_ascii=False)

    except KeyError as e:
        try:
            from triage_core.playbooks import registry as pb_registry

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
        from triage_core.playbooks import registry as pb_registry

        playbooks = pb_registry.list_all()

        if filter_mitre:
            playbooks = [p for p in playbooks if any(filter_mitre.upper() in mid.upper() for mid in p["mitre_ids"])]
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
async def list_playbooks_json() -> str:
    """Lists all registered SOC playbooks in JSON format."""
    logger.info("tool.list_playbooks_json")
    try:
        import json

        from triage_core.playbooks import registry as pb_registry

        playbooks = pb_registry.list_all()
        return json.dumps(playbooks, ensure_ascii=False)
    except Exception as e:
        logger.error("playbook.list_json.error", error=str(e))
        return json.dumps({"error": f"Error fetching playbook list: {str(e)}"}, ensure_ascii=False)


@mcp.tool()
async def get_playbook_details(playbook_id: str) -> str:
    """Gets the detailed steps and description of a registered SOC playbook by its ID (as a JSON string)."""
    logger.info("tool.get_playbook_details", playbook_id=playbook_id)
    try:
        from triage_core.playbooks import registry as pb_registry

        pb = pb_registry.get(playbook_id)

        steps_data = []
        for s in pb.steps:
            steps_data.append(
                {
                    "order": s.order,
                    "title": s.title,
                    "group": s.group,
                    "description": s.description,
                    "tool": s.tool_hint or "system",
                    "approval": s.approval_gate.requires_confirmation_for if s.approval_gate else None,
                }
            )

        import json

        return json.dumps(
            {
                "id": pb.id,
                "name": pb.name,
                "description": pb.description,
                "mitre_ids": pb.mitre_ids,
                "severity": pb.severity.value.upper(),
                "steps": steps_data,
            },
            ensure_ascii=False,
        )
    except KeyError:
        return f"Playbook '{playbook_id}' not found."
    except Exception as e:
        logger.error("playbook.details.error", playbook_id=playbook_id, error=str(e))
        return f"Error fetching playbook details: {str(e)}"


@mcp.tool()
async def find_playbook_for_alert(
    rule_id: str = "",
    mitre_ids: list[str] | None = None,
) -> str:
    """Finds the most suitable playbook for a given rule ID or MITRE technique IDs."""
    logger.info("tool.find_playbook_for_alert", rule_id=rule_id, mitre_ids=mitre_ids)
    try:
        from triage_core.playbooks import registry as pb_registry

        candidates = pb_registry.find_for_alert(rule_id=rule_id, mitre_ids=mitre_ids or [])

        if not candidates:
            return (
                f"No suitable playbook found for Rule ID '{rule_id}' or MITRE {mitre_ids}.\n"
                f"Use the list_playbooks tool to see all playbooks."
            )

        lines = [f"Suitable playbooks ({len(candidates)} found):\n"]
        for pb in candidates:
            lines.append(f"  → **{pb.id}**: {pb.name} [{pb.severity.value.upper()}] MITRE: {', '.join(pb.mitre_ids)}")
        lines.append(f"\nTo trigger the playbook: trigger_playbook(playbook_id='{candidates[0].id}', ...)")
        return "\n".join(lines)
    except Exception as e:
        logger.error("playbook.find.error", error=str(e))
        return f"Playbook search error: {str(e)}"


# ─────────────────────────────────────────────────────────────────────────────
# Case Management Tools
# ─────────────────────────────────────────────────────────────────────────────


@mcp.tool()
async def create_case(title: str = "", description: str = "", severity: int = 2, tags: list[str] | None = None) -> str:
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
async def update_case_status(
    case_id: str, status: str, resolution_type: str = "TruePositive", summary: str = ""
) -> str:
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
async def create_alert(
    title: str = "",
    description: str = "",
    source: str = "Agentix",
    source_ref: str = "",
    severity: int = 2,
    tags: list[str] | None = None,
    observables: list[dict[str, Any]] | None = None,
) -> str:
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
async def trigger_soar_workflow(workflow_id: str, data: dict[str, Any] | None = None, webhook_url: str = "") -> str:
    """Triggers a workflow on SOAR."""
    provider = registry.get_soar_provider()
    return await provider.trigger_workflow(workflow_id, data, webhook_url)
