# System Architecture Overview

This document provides a detailed view of the BlueTeam / Agentix architecture using the C4 model for software architecture.

---

## 1. C4 Context Diagram (Level 1)

This diagram shows the system in the context of the external actors and platforms it interacts with.

```mermaid
graph TB
    Analyst([SOC Analyst / DevSecOps Engineer]) -->|Interacts with UI / triggers triage| BlueTeamSystem[("BlueTeam / Agentix Platform")]
    
    subgraph Detections & Alerts
        WazuhSIEM[Wazuh SIEM] -->|Sends alerts / events| BlueTeamSystem
    end

    subgraph Security Operations Core
        BlueTeamSystem -->|Enriches IOCs| Cortex[Cortex Enrichment API]
        BlueTeamSystem -->|Manages cases & tasks| TheHive[TheHive Case Management]
    end

    subgraph External Platforms
        BlueTeamSystem -->|Verifies reputational data| VirusTotal[VirusTotal API]
        BlueTeamSystem -->|Queries IP data| AbuseIPDB[AbuseIPDB API]
    end
```

---

## 2. C4 Container Diagram (Level 2)

This diagram details the containerized services that run within the BlueTeam/Agentix environment and how they communicate.

```mermaid
graph TD
    Client([SOC Analyst / API Client]) -->|HTTP / JSON + JWT| Gateway[API Gateway Service]
    
    subgraph Agentix Core App
        Gateway -->|HTTP Auth / Internal API Key| Orchestrator[Agentix Orchestrator Engine]
        Orchestrator -->|Memory Operations| Redis[Redis Cache / Memory DB]
        Orchestrator -->|Dynamic Embeddings| Postgres[(PostgreSQL + pgvector)]
        Orchestrator -->|JSON / Chat Call| LLM[LLM Strategy / BaseLLMClient]
    end

    LLM -->|REST API| ExternalLLM[Cloud LLMs: OpenAI / Gemini]
    LLM -->|HTTP| LocalOllama[Local LLM: Ollama]

    subgraph SOC Tool Layer
        Orchestrator -->|Model Context Protocol SSE| TriageCore[SOC FastMCP Server]
        TriageCore -->|Internal TCP| WazuhAPI[Wazuh Manager API]
        TriageCore -->|Internal TCP| TheHiveAPI[TheHive API]
        TriageCore -->|Internal TCP| CortexAPI[Cortex API]
    end

    subgraph Docker Infrastructure
        WazuhAPI
        TheHiveAPI
        CortexAPI
    end
```

---

## 3. Component Diagram: Agentix Orchestration Core (Level 3)

This diagram highlights the internal Python modules and classes within the `Agentix` package that control agent behavior.

```mermaid
classDiagram
    class Orchestrator {
        +run_session(agent_id, prompt)
        +execute_loop()
        -handle_tool_call(tool_call)
    }
    class AgentRouter {
        +route_request(user_prompt) AgentPersona
    }
    class AgentPersona {
        +agent_id: str
        +system_prompt: str
        +allowed_tools: list~str~
    }
    class SessionWorkspace {
        +session_id: str
        +root_dir: Path
        +resolve_safe_path(relative_path) Path
    }
    class LLMFactory {
        +get_client(provider_name) BaseLLMClient
    }
    class BaseLLMClient {
        <<interface>>
        +generate_completion(messages, tools) CompletionResponse
    }
    class FastMCPClient {
        +list_tools() list
        +call_tool(tool_name, arguments) dict
    }

    Orchestrator --> AgentRouter : Routes prompt
    AgentRouter --> AgentPersona : Loads YAML
    Orchestrator --> SessionWorkspace : Sandboxes I/O
    Orchestrator --> LLMFactory : Fetches client
    LLMFactory ..> BaseLLMClient : Instantiates
    Orchestrator --> FastMCPClient : Invokes remote tools
```

---

## 4. Architectural Safeguards

1. **Path-Traversal Validation**: The `SessionWorkspace` checks all file path arguments against the workspace root. If a path contains `../` or resolves to a location outside the session folder, it is rejected before any filesystem operations occur.
2. **HITL Gates**: Any tool flagged with `requires_confirmation=True` automatically raises a `PendingApproval` exception. This pauses execution, saves the session state (draft logs), and prompts the operator for approval.
3. **Execution Iteration Cap**: To prevent infinite agent reasoning loops (e.g. LLM getting stuck calling the same failing tool), a maximum iteration limit (`AGENTIX_MAX_ITERATIONS`, defaults to 10) is strictly enforced.
4. **Sandbox Process Group Timeout Isolation**: Subprocesses executed via the sandbox ([executor.py](file:///Users/firatkurt/Documents/Repos/blueTeam/src/Agentix/agentix/sandbox/executor.py)) are instantiated in a dedicated process group (`process_group=0`). When a command times out, the entire process group is killed via `os.killpg(proc.pid, signal.SIGKILL)`, ensuring no orphaned background processes (zombies) remain.
5. **Lightweight Circuit Breaker**: The MCP adapter ([mcp_adapter.py](file:///Users/firatkurt/Documents/Repos/blueTeam/src/Agentix/agentix/tools/mcp_adapter.py)) features a lightweight circuit breaker that tracks downstream tool connection failures. If 5 consecutive failures occur, the circuit opens for 30 seconds, immediately rejecting downstream calls to preserve platform responsiveness.
6. **Dictionary Size Validation**: High-impact tools limit input payload dictionary sizes (e.g. `extra_context` and `data` in [soc_tools.py](file:///Users/firatkurt/Documents/Repos/blueTeam/src/TriageCore/triage_core/tools/soc_tools.py)) to a maximum of 64KB JSON-serialized payload size to prevent memory exhaustion (OOM) or database serialization failures.
7. **Database Migration Advisory Lock**: Database migration execution ([postgres_session.py](file:///Users/firatkurt/Documents/Repos/blueTeam/src/AgenticCommon/agentic_common/memory/postgres_session.py)) employs a session-level PostgreSQL advisory lock (`42424242`) to prevent race conditions or schema corruption when multiple instances run parallel schema upgrades on startup.
