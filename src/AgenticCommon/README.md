# AgenticCommon

**Shared Core Components for Agentix and MCP Ecosystems**

AgenticCommon is the foundational library that provides shared infrastructure, telemetry, workspaces, and database connectivity for the entire Agentix orchestration platform.

## Quickstart

### Installation

AgenticCommon is managed via `uv` or standard Python package managers. It requires Python 3.12+.

```bash
uv add path/to/agentic_common
```

### Development Setup

To work on AgenticCommon itself:

```bash
cd src/AgenticCommon
uv sync
uv run pytest
```

## Structure

- **Settings**: Centralized configuration management using `pydantic-settings`.
- **Workspace**: Secure, sandboxed file operations for agent sessions.
- **Vectors/Memory**: Database models for PgVector and Redis-based session storage.
- **Telemetry**: Shared `structlog` configurations for consistent observability across services.

For an in-depth architectural look, please refer to the [DOCUMENTATION.md](./DOCUMENTATION.md).
