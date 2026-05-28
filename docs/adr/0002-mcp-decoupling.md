# Model Context Protocol Decoupling

* Status: accepted
* Deciders: Architect, Lead Security Engineer
* Date: 2026-05-28

## Context and Problem Statement

The core agent framework (`Agentix`) runs code that interacts with the LLM. However, security operations platforms like Wazuh, TheHive, and Cortex require highly sensitive API keys, administrator credentials, and direct access to secure networks. Coupling all these APIs directly into the `Agentix` process makes it hard to secure: if the LLM compromises the agent's memory or context, the keys could be leaked. Additionally, running integrations in the same process increases code dependencies and makes scaling/updating individual security tool connections highly risky.

## Decision Drivers

* **Zero-trust credential isolation**: The LLM engine must never have direct visibility or access to the underlying security API keys.
* **Component decoupling**: Keep tool integrations independent of core ReAct loop orchestration.
* **Standards-aligned**: Align with modern open-source tool standards.

## Considered Options

1. **Embedded Integrations**: Place Wazuh, TheHive, and Cortex client libraries directly in the core orchestrator python packages.
2. **Model Context Protocol (MCP) Decoupling**: Run integrations in a separate microservice (`SOCMCP`) exposing its capabilities as FastMCP SSE/Stdio tools. The core orchestrator communicates with the MCP server to obtain tool listings and trigger executions.

## Decision Outcome

Chosen option: **Option 2 (Model Context Protocol Decoupling)**. We deploy `SOCMCP` as a standalone service using the `fastmcp` Python library. It handles authentication and communication with Wazuh, Cortex, and TheHive internally, and only exposes clean functional schemas to the `Agentix` orchestrator.

### Positive Consequences

* **Credential Isolation**: Security credentials (like `THEHIVE_API_KEY` or `WAZUH_API_PASSWORD`) remain exclusively inside the `SOCMCP` container. The core `Agentix` service only knows how to send JSON requests to the MCP endpoint.
* **Independent Lifecycle**: If Wazuh or TheHive APIs change, only the `SOCMCP` component needs updating. The core orchestration code remains untouched.
* **Standardization**: Adapting to Anthropic's Model Context Protocol allows the tools to be reused with other MCP-compliant agents or developer tools.

### Negative Consequences

* **Extra Overhead**: Communication between the orchestrator and tools requires network requests (SSE/HTTP), which introduces minor network latency (~5-20ms per tool invocation).
* **Multiple Containers**: Adds operational complexity, requiring multiple docker services to be orchestrated together.
