# ReAct Loop Orchestration

* Status: accepted
* Deciders: Architect, Lead AI Engineer
* Date: 2026-05-28

## Context and Problem Statement

Security incidents are dynamic and unpredictable. A standard static DAG (Directed Acyclic Graph) of operations or a predefined checklist (e.g. "always search SIEM then block IP") is too rigid for complex incident triage. For example, if a suspicious connection is found, the agent might need to perform an IP enrichment, check internal asset databases, check local login logs, and then decide to isolate a host. We need an agent reasoning framework that can decide the next step dynamically based on the outputs of the previous steps.

## Decision Drivers

* Dynamic decision capability based on runtime information.
* Support for parallel tool executions (e.g., enriching multiple IPs simultaneously).
* Prevention of infinite execution loops.

## Considered Options

1. **State-Machine Workflow (e.g. LangGraph / Static DAG)**: Define a fixed flowchart of analysis states.
2. **ReAct Loop (Reason + Act)**: The agent operates in an iterative loop:
   - **Think**: Model decides what to do based on task goals and historical logs.
   - **Act**: Model emits a tool call.
   - **Observe**: Tool runs, returning output to the context history.
   - Repeat until the model decides to **Answer**.

## Decision Outcome

Chosen option: **Option 2 (ReAct Loop)**. Implemented in `src/Agentix/agentix/core/orchestrator.py`, the ReAct loop gives the agent maximum flexibility to adapt to incident details. We wrap the loop with strict execution safeguards: `AGENTIX_MAX_ITERATIONS` to prevent runaway reasoning loops and explicit error handling at each turn.

### Positive Consequences

* **Adapts to Unknown Alerts**: The agent can handle arbitrary alerts by reasoning about the context on the fly.
* **Simplifies Agent Definition**: Instead of drawing complex node transitions, developer-defined personas only need a YAML configuration describing system prompt rules and allowed tools.

### Negative Consequences

* **Runaway Loop Risk**: If an observation is confusing or throws an unhandled exception, the LLM might query the same tool repeatedly. Guarding with maximum iteration checks is mandatory.
* **Debugging Complexity**: Tracking the internal thought steps of the agent requires structured tracing (using Langfuse) since the execution path changes dynamically.
