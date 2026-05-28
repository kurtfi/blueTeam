# Human-In-The-Loop Confirmation Flow

* Status: accepted
* Deciders: Architect, Lead Security Engineer
* Date: 2026-05-28

## Context and Problem Statement

Autonomous agents are powerful but prone to errors, hallucinations, and prompt injection attacks. If an agent has access to containment tools (e.g. blocking active directory accounts, shutting down servers, or blacklisting IPs on firewalls), allowing it to run these actions fully autonomously poses a critical business risk:
1. It could block the IP of a legitimate business partner due to a false alarm.
2. It could shut down a critical production server.
3. An attacker could trick the agent into executing destructive commands via prompt injection.

We need a mechanism that halts the agent's execution, presents proposed actions to a human analyst, and only resumes after approval.

## Decision Drivers

* **Safety & Security**: Prevent unauthorized or accidental containment actions.
* **Seamless API Resume**: Support pausing and resuming agent session states over HTTP APIs.
* **Auditability**: Track who approved what action and when.

## Considered Options

1. **Fully Autonomous Containment**: Allow the agent to call active containment tools automatically.
2. **Human-In-The-Loop (HITL) Gate with Draft History**: Flag sensitive tools as `requires_confirmation=True`. When the agent decides to execute one of these tools:
   - The orchestrator intercepts the tool call.
   - The orchestrator saves the current execution state (draft history) to the database and pauses the session.
   - The API returns a `PENDING_APPROVAL` status back to the analyst.
   - Once the analyst clicks "Approve" (or "Reject"), the session resumes execution with the approved parameters.

## Decision Outcome

Chosen option: **Option 2 (HITL Gate with Draft History)**. Implemented using draft session logs in `src/Agentix/agentix/core/orchestrator.py` and tested in `src/Agentix/tests/test_draft_history.py`. This ensures high-risk operations cannot execute without a signature/explicit approval from a human analyst.

### Positive Consequences

* **Reduced Risk**: Drastically lowers the risk of false positives causing business disruption.
* **Security Controls**: Fulfills enterprise compliance requirements (e.g., SOC2, ISO 27001) for automated system changes.

### Negative Consequences

* **Increased Latency**: Requires human response times, preventing fully immediate autonomous response (which is an acceptable trade-off for critical changes).
* **State Management Complexity**: The API must handle state serialization, allowing sessions to be persisted and resumed hours later.
