# TriageCore: Technical Reference Manual

**Version**: 0.1.0  
**Status**: Production  
**Scope**: FastMCP Server for Security Operations

---

## 1. Executive Summary

`TriageCore` is an externalized Model Context Protocol (MCP) server dedicated to Security Operations Center (SOC) tasks. By decoupling these high-privilege, specialized tools from the main Agentix orchestrator, the platform maintains a strict boundary of concerns. `TriageCore` specifically empowers the Agentix "SOC Triage (T1)" persona to interact autonomously with security platforms like Wazuh, Cortex, TheHive, and SOAR providers.

---

## 2. Architecture Overview

### FastMCP Integration
`TriageCore` runs as a standalone Python process wrapping the [FastMCP](https://github.com/jlowin/fastmcp) framework. It exposes its endpoints via Server-Sent Events (SSE) on port `8081` (configurable via `FASTMCP_PORT`).

When the Agentix orchestrator initializes, it connects to this SSE stream, retrieves the tool definitions, and injects them into the semantic `ToolCatalog`.

---

## 3. Core Components

### 3.1 SOC Tools (`soc_tools.py`)
This module contains the primary logic for security integrations. It registers tools directly onto the FastMCP application instance.

**Example Capabilities**:
- **Alert Fetching**: Pulling unacknowledged alerts from SIEM platforms.
- **Enrichment**: Querying Cortex analyzers or Threat Intelligence Platforms (TIPs) for IOC (Indicator of Compromise) verdicts.
- **Incident Management**: Creating or updating cases in TheHive.

### 3.2 Error Handling & Resilience
Security APIs often have rate limits or require complex authentication flows. The TriageCore server utilizes structured logging (via `AgenticCommon`) to emit debug traces when tools fail to load or when upstream APIs timeout, preventing the main orchestrator from hanging.

---

## 4. Security Model

### 4.1 Credential Management
`TriageCore` requires privileged API keys to interact with the SOC ecosystem (Wazuh, Cortex, etc.). These credentials are injected purely through the environment (e.g., via `.env` or Kubernetes Secrets) and are **never** passed from the Agentix orchestrator. 

This means the LLM reasoning engine never has direct access to the raw API keys, mitigating severe risks associated with prompt injection data exfiltration.

### 4.2 Network Isolation
By running `TriageCore` as a separate microservice, it can be placed within a strict network segment (e.g., inside the management VLAN) with firewalls allowing only inbound connections from the Agentix core, protecting the sensitive SOC APIs from direct internet exposure.

---

## 5. Integration Points

To add a new SOC tool:
1. Define the asynchronous function in `soc_tools.py`.
2. Decorate it with `@mcp.tool()` to expose it via the protocol.
3. Use Pydantic models for argument validation to ensure the LLM sends well-structured JSON data.
4. The Agentix orchestrator will automatically pick up the new tool upon restarting its MCP adapter connection.
