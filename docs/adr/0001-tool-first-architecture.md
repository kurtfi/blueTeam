# Tool-First Architecture

* Status: accepted
* Deciders: Architect, Lead AI Engineer
* Date: 2026-05-28

## Context and Problem Statement

Security operations involve interacting with real, production-critical tools and infrastructure (SIEMs, case management, active firewalls, endpoint agents). Hardcoding these actions directly into the core execution flows of the AI agent leads to high coupling, difficult testing, and major security issues. Additionally, LLMs are known to suffer from hallucination and lack real-time visibility into local networks or state. We need a way to bind actions to the LLM while keeping them highly modular, testable, and secure.

## Decision Drivers

* Maintain strict separation between reasoning (LLM) and execution (code).
* Enable developers to add new capabilities without altering core agent logic.
* Ensure all agent actions can be intercepted, logged, and audited.

## Considered Options

1. **Hardcoded Agent Logic**: Incorporate API calls (e.g. Wazuh client calls) directly inside the agent orchestration scripts.
2. **Tool-First Architecture**: Define all capabilities as structured, descriptive functions (tools) registered in a registry. The LLM acts as the orchestrator, dynamically invoking tools and receiving results.

## Decision Outcome

Chosen option: **Option 2 (Tool-First Architecture)**, because it treats the LLM purely as a stateless decision engine. The agent reads tool schemas, reasons about what action to perform, and emits tool calls. The framework executes these tools and feeds back the observations.

### Positive Consequences

* **High Extensibility**: Adding a new integration or command is as simple as creating a new Python tool definition and registering it.
* **Testability**: Tools can be mocked or unit-tested in isolation (e.g. using `pytest`) without spinning up the main agent orchestrator.
* **Security & Observability**: Every execution has a unified gateway, allowing us to enforce permissions (e.g., Human-In-The-Loop) and log all telemetry.

### Negative Consequences

* **Latency**: Multi-turn ReAct loops require multiple round-trips to the LLM provider, increasing token usage and execution latency.
* **Context Overload**: Registering too many tools can exhaust the LLM's system prompt context, requiring advanced pruning mechanisms.
