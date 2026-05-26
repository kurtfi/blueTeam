# Agentix

**Tool-First AI Orchestration Platform**

Agentix is a modular and extensible AI agent platform built around a central orchestrator. It breaks down user requests into atomic tasks and executes them with dynamically selected tools (Tool Registry).

---

## Principles

| # | Principle | Description |
|---|---------|----------|
| 1 | **Dynamic Tool Selection** | Only tools matching the user intent are loaded into context per request. |
| 2 | **Chain of Thought (CoT)** | Think → Act → Observe → Answer loop (ReAct). |
| 3 | **Stateless Logic / Stateful Experience** | Business logic remains pure; context is managed at the `memory` layer. |
| 4 | **Safety First** | Sandboxing and permission checks are mandatory for critical operations. |

---

## Folder Structure

```
src/Agentix/
├── main.py                        # Entry point
├── pyproject.toml
├── .env.example
└── agentix/
    ├── core/
    │   ├── settings.py            # Env-based config (pydantic-settings)
    │   ├── llm.py                 # Async OpenAI wrapper
    │   ├── react.py               # ReAct trace data structures
    │   └── orchestrator.py        # ← Central orchestrator
    ├── tools/
    │   ├── base.py                # BaseTool + ToolResult (abstract contract)
    │   ├── system.py              # FileManager, SandboxedTerminal
    │   ├── data.py                # SQLConnector, RAGSearch
    │   ├── action.py              # MailService, MessagingBridge
    │   └── ux.py                  # SessionTracker, PreferenceManager
    ├── memory/
    │   ├── session.py             # Conversation history + session metadata
    │   └── preferences.py         # User preferences (multi-session)
    ├── registry/
    │   ├── catalog.py             # ToolCatalog — registration + dynamic selection
    │   └── schemas/
    │       └── file_manager.json  # Example JSON schema
    └── sandbox/
        └── executor.py            # Secure subprocess runner
```

---

## Quick Start

```bash
cd src/Agentix
uv sync
cp .env.example .env
# Add OPENAI_API_KEY to .env file

uv run python main.py
```

---

## Adding a New Tool

### 1. Write the class

```python
# agentix/tools/my_module.py
from agentix.tools.base import BaseTool, ToolResult

class WeatherTool(BaseTool):
    name        = "weather"
    description = "Fetch current weather for a given city."
    category    = "data"
    parameters  = {
        "type": "object",
        "properties": {
            "city": {"type": "string", "description": "City name."},
        },
        "required": ["city"],
    }

    async def execute(self, city: str, **_) -> ToolResult:
        # ... real implementation
        return ToolResult(success=True, output={"city": city, "temp_c": 22})
```

### 2. Register to the catalog

```python
# inside main.py
catalog.register(WeatherTool())
```

### 3. Add JSON schema (optional)

Save the `BaseTool.to_registry_entry()` output to the `agentix/registry/schemas/weather.json` file.

---

## Tool Categories and MCP Integrations

To maintain modularity, Agentix has exported high-resource and security-sensitive tools as **FastMCP servers**:

| MCP Server | Category | Tools | Description |
|--------------|----------|---------|----------|
| **GeneralMCP** | Data     | DoclingParser, Crawl4AI, RAGSearch | Data processing, web scraping, and PDF reading. |
| **GeneralMCP** | System   | FileManager, Terminal | Protected file management and shell access. |
| **GeneralMCP** | Action   | MailService, APIConnector | API and email access to external services. |
| **SOCMCP**     | Security | Wazuh, Cortex, TheHive, SOAR | Security platform integrations for L1 SOC analysts. |

Additionally, all logging, database, memory, and workspace operations have been moved to the **`AgenticCommon`** shared library.
---

## Architecture Flow

```
User Request
     │
     ▼
Orchestrator.run()
     │
     ├─ 1. SessionStore → load conversation history
     ├─ 2. ToolCatalog.select() → select intent-matching tools
     ├─ 3. LLMClient.chat() → start ReAct loop
     │       │
     │       ├── Think  → LLM decides what to do
     │       ├── Act    → Tool call is made
     │       ├── Observe → Result is fed back to LLM
     │       └── ...repeat until Final Answer
     │
     └─ 4. SessionStore → update history → return ReActTrace
```

---

## Development

```bash
# Linting
uv run ruff check .

# Type checking
uv run mypy agentix/

# Tests
uv run pytest
```
