# Playbook Development & Execution Guide

This guide details how to develop, configure, and register custom Security Operations Center (SOC) playbooks in the **BlueTeam / Agentix** platform.

---

## 1. What is an Agentix Playbook?

An Agentix Playbook is a structured, step-by-step incident response routine written in Python. Unlike static text documents, these playbooks:
* Are parsed and executed dynamically by the AI agent.
* Automatically interpolate alert context variables (e.g., agent IDs, source IPs) into instructions.
* Explicitly specify which tools should be run at each phase.
* **Gate high-risk actions** (like endpoint isolation or blocking accounts) using human approval checkpoints (`ApprovalGate`).

All playbooks are stored and managed inside the `TriageCore` server (`src/TriageCore/triage_core/playbooks/`).

---

## 2. Playbook Data Models

Playbooks are composed of three primary Python data structures defined in `triage_core/playbooks/base.py`:

### 2.1. `Playbook`
The wrapper class defining the metadata, template links, and list of steps:
* `id` (str): Unique identifier (e.g., `PB-008`).
* `name` (str): Descriptive title.
* `description` (str): Overview of what the playbook remediates.
* `mitre_ids` (list[str]): Associated MITRE ATT&CK technique IDs (e.g., `["T1078", "T1078.001"]`).
* `severity` (Severity): Default threat severity (`low`, `medium`, `high`, `critical`).
* `steps` (list[PlaybookStep]): Ordered list of execution steps.
* `case_template` (str): Matching Case Template name to use when creating a ticket in TheHive.

### 2.2. `PlaybookStep`
Represents an individual task in the response timeline:
* `order` (int): 0-indexed execution order.
* `title` (str): Short description of the step.
* `group` (str): Phase category (`Investigation`, `Enrichment`, `Containment`, `Remediation`, `Reporting`).
* `tool_hint` (str | None): The name of the MCP tool the agent should execute for this step.
* `parameters` (dict): Argument templates mapped to context.
* `approval_gate` (ApprovalGate | None): If set, forces the agent to request confirmation before executing.

### 2.3. `ApprovalGate`
Blocks automated execution until a human analyst confirms the action:
* `message` (str): Question prompted to the analyst.
* `requires_confirmation_for` (str): Human-readable summary of the action being gated.

---

## 3. Creating and Registering a Playbook

Follow these steps to implement a custom playbook.

### Step 1: Define the Playbook Object
Open `src/TriageCore/triage_core/playbooks/soc_playbooks.py` and define your playbook instance.

Here is an example of creating `PB-008` for **Privileged Account Creation (`T1136.001`)**:

```python
from triage_core.playbooks.base import Playbook, PlaybookStep, ApprovalGate, Severity

PB_008 = Playbook(
    id="PB-008",
    name="Persistence - Local Account Creation T1136.001",
    description=(
        "Triggered when a new privileged local account is created on a host. "
        "Indicates possible attacker attempts to establish persistent access. "
        "Immediate audit, user deletion, and credential resets required."
    ),
    mitre_ids=["T1136", "T1136.001"],
    severity=Severity.HIGH,
    tags=["persistence", "account-creation", "linux"],
    case_template="MITRE T1136.001 - Account Creation",
    steps=[
        PlaybookStep(
            order=0,
            title="Query SIEM - Identify Creator and Username",
            group="Investigation",
            description=(
                "Search Wazuh logs for user addition events (rule.id: 5104 or 5105) "
                "on agent ctx.agent_id. Extract the created account name and creator context."
            ),
            tool_hint="query_siem_logs",
            parameters={"query": "rule.id:(5104 OR 5105) AND agent.id:ctx.agent_id"},
        ),
        PlaybookStep(
            order=1,
            title="Create Case in TheHive",
            group="Investigation",
            description=(
                "Open a new incident case in TheHive with high severity."
            ),
            tool_hint="create_case",
            parameters={
                "title": "[T1136.001] Unauthorized Account Creation on ctx.agent_name",
                "severity": 3,
                "tags": ["mitre", "t1136.001", "persistence"],
            },
        ),
        PlaybookStep(
            order=2,
            title="Disable and Delete Malicious Account",
            group="Containment",
            description=(
                "Disable the newly created user account to prevent session logins."
            ),
            tool_hint="disable_user_account",
            parameters={"username": "ctx.alert.created_user"},
            approval_gate=ApprovalGate(
                message=(
                    "⚠️ Warning: You are about to disable account ctx.alert.created_user "
                    "on host ctx.agent_name. Proceed? [yes/no]"
                ),
                requires_confirmation_for="Disable user account ctx.alert.created_user",
            ),
        ),
        PlaybookStep(
            order=3,
            title="Add Case Notes",
            group="Reporting",
            description="Add final execution summary to TheHive.",
            tool_hint="add_case_note",
            parameters={
                "case_id": "ctx.case_id",
                "note": "PB-008 executed. Account ctx.alert.created_user disabled. Case escalated for DFIR audit.",
            },
        ),
    ]
)
```

### Step 2: Context Value Interpolation
Placeholders prefixed with `ctx.` inside strings are dynamically evaluated at runtime against the `PlaybookContext` data structure:
* `ctx.agent_id` resolves to the Wazuh agent ID.
* `ctx.agent_name` resolves to the hostname.
* `ctx.src_ip` resolves to the attacker source IP.
* `ctx.alert.xxx` accesses nested fields within the raw alert dictionary (e.g. `ctx.alert.created_user` matches the `created_user` key inside the alert).
* `ctx.case_id` resolves to the created case's ID (populated dynamically during step execution).

### Step 3: Register in Playbook Registry
At the bottom of `src/TriageCore/triage_core/playbooks/soc_playbooks.py`, locate where playbooks are registered to the registry singleton:

```python
from triage_core.playbooks.registry import PlaybookRegistry

# Register your new playbook instance
PlaybookRegistry.instance().register_many(
    PB_001,
    PB_002,
    PB_003,
    PB_004,
    PB_005,
    PB_006,
    PB_007,
    PB_008,  # <- Added
)
```

---

## 4. How the AI Agent Executes Playbooks

Playbooks are exposed to the AI agent as tools through the `TriageCore` FastMCP server. The execution lifecycle is fully automated:

1. **Detection Match**: When an alert is processed, the agent calls `find_playbook_for_alert(rule_id=..., mitre_ids=...)` to check if a structured playbook exists for the specific alert or MITRE technique.
2. **Retrieve Instructions**: The agent calls `trigger_playbook(playbook_id=..., ...)` passing the current alert context.
3. **Execution Loop**:
   - The agent parses the returned markdown list of steps.
   - It executes each step sequentially, matching the `tool_hint` to its local tool registrations.
   - When encountering a step flagged with `requires_confirmation=True` (due to an `ApprovalGate`), the orchestrator catches it, saves the session draft to Redis, and returns a `PENDING_APPROVAL` status back to the frontend/Gateway.
   - Once approved, the orchestrator retrieves the session state and runs the containment tool to complete the playbook.
