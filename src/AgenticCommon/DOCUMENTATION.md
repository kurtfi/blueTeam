# AgenticCommon: Technical Reference Manual

**Version**: 0.1.0  
**Status**: Production  
**Scope**: Shared Library for Agentix and MCP Servers

---

## 1. Executive Summary

`AgenticCommon` serves as the foundational, shared logic layer for the Agentix platform. To prevent code duplication and ensure consistent behavior across the main `Agentix` orchestrator and its decoupled tools (like `TriageCore` and `GeneralMCP`), core components have been consolidated into this single library. 

This ensures that logging formats, workspace path resolutions, and configuration validations remain identical whether a process is running in the core orchestrator or in an edge MCP server.

---

## 2. Core Components

### 2.1 Workspace (`workspace.py`)
The `SessionWorkspace` manages the secure, sandboxed file system environment for each agent session.
- **Isolation**: Prevents path traversal vulnerabilities (`../../`) by enforcing operations to remain strictly within the session's designated root directory.
- **Structure**: Automatically creates subdirectories like `downloads`, `uploads`, `temp`, and `outputs`.
- **Quotas**: Monitors and limits file sizes and total directory sizes to prevent resource exhaustion attacks.

### 2.2 Telemetry (`telemetry.py`)
Provides a unified logging configuration using `structlog`.
- Outputs JSON logs suitable for centralized aggregation (e.g., ELK, Datadog).
- Automatically binds session IDs and context keys across asynchronous boundaries to provide end-to-end trace visibility.

### 2.3 Settings (`settings.py`)
Uses `pydantic-settings` for robust, type-checked environment variable parsing.
- Enforces required environment variables at boot time.
- Standardizes configuration variable names across microservices.

### 2.4 Embeddings (`embeddings.py`)
Provides standard interfaces for vector embeddings used by native RAG operations and semantic search features, ensuring that all components produce compatible vector spaces.

### 2.5 Base Tool (`base_tool.py`)
Defines the `BaseTool` class contract that was originally part of Agentix. All tools across `Agentix`, `TriageCore`, and `GeneralMCP` inherit from this class to guarantee a uniform API containing:
- `name`
- `description`
- `parameters` schema
- `execute()` asynchronous interface

---

## 3. Data Models

The library encapsulates common data interactions:
- **`memory/`**: Models for conversational state and memory persistence, utilizing Redis for fast session retrieval.
- **`vectors/`**: SQLAlchemy and asyncpg configurations for interacting with PostgreSQL/PgVector, which stores documents and semantic embeddings for the Native RAG system.

---

## 4. Integration Points

When creating a new MCP server for the Agentix ecosystem:
1. Include `agentic_common` in your `pyproject.toml`.
2. Inherit from `BaseTool` for your FastMCP exposed endpoints.
3. Use the unified `telemetry.py` setup to initialize `structlog` for logging consistency.
4. Utilize `SessionWorkspace` if your tools require filesystem access, ensuring security invariants are met.
