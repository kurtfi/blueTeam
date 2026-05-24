# SOCMCP

**Security Operations Center MCP Server for Agentix**

SOCMCP provides a FastMCP-compliant server that exposes enterprise security operations tools to the Agentix orchestrator. It acts as the bridge between the AI agents and standard SOC platforms like Wazuh, Cortex, TheHive, and Shuffle.

## Quickstart

### Environment Setup

Create a `.env` file containing the credentials for the security platforms.

```env
# FastMCP configuration
FASTMCP_PORT=8081
FASTMCP_TRANSPORT=sse

# Add Wazuh, Cortex, TheHive credentials here if needed
```

### Running the Server

Start the SOCMCP FastMCP server using `uv`:

```bash
cd src/SOCMCP
uv sync
uv run python soc_mcp/main.py
```

The server runs on port `8081` using Server-Sent Events (SSE) by default.

### Features

- Provides SOC specific tools like IP reputation lookups, alert triage, and incident creation.
- Seamlessly integrates with `agentic_common` for unified logging and tool interfaces.
- Can be dynamically consumed by the Agentix Orchestrator or any standard MCP client.

For deep architectural details, see [DOCUMENTATION.md](./DOCUMENTATION.md).
