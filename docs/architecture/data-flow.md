# End-to-End Data Flow

This document details the data pipelines and state transitions inside the BlueTeam / Agentix platform during session execution, dynamic tool selection, and human approval gates.

---

## 1. Request Lifecycle & ReAct Loop Flow

When a user submits an alert investigation request via the API, the system initiates a structured processing flow.

```mermaid
sequenceDiagram
    autonumber
    actor Analyst as SOC Analyst
    participant API as API Gateway / App
    participant Router as Agent Router
    participant RAG as RAG Injector
    participant DB as Postgres/Vector DB
    participant Orch as Orchestrator
    participant Sandbox as Session Sandbox
    participant MCP as SOC MCP Server

    Analyst->>API: POST /api/v1/investigate {agent_id, prompt}
    API->>API: Validate Authorization Header (Bearer JWT/API Key)
    
    API->>Router: Route Request (Identify matching persona)
    Router-->>API: Return AgentPersona Configuration
    
    API->>RAG: Extract context matching alert metadata
    RAG->>DB: Query similarity for plays/procedures
    DB-->>RAG: Return relevant markdown chunks
    RAG-->>API: Return compiled system prompt context
    
    API->>Orch: Initialize Session (load context, persona, RAG info)
    Orch->>Sandbox: Create isolated sandbox workspace directory
    
    loop ReAct Loop (Up to MAX_ITERATIONS)
        Orch->>Orch: Assemble conversation history
        Orch->>Orch: Ask LLM: "Think: What action should I take?"
        Orch->>MCP: Call tool (e.g. read_wazuh_alerts) with JSON parameters
        MCP->>MCP: Authenticate using container-isolated credentials
        MCP->>Sandbox: Run tool & read/write within workspace
        Sandbox-->>MCP: Tool observation data
        MCP-->>Orch: Return JSON observation payload
        Orch->>Orch: Append observation to history logs
    end

    Orch->>API: Return finalized investigation analysis markdown
    API-->>Analyst: HTTP 200 OK with response payload
```

---

## 2. Dynamic Tool Selection Flow

To optimize context window consumption and prevent LLM confusion, we dynamically load tool descriptors into the model instruction on the fly.

```mermaid
flowchart TD
    Start[User Prompt Received] --> Route[Router matches Prompt to Agent Persona]
    Route --> LoadPersona[Load Persona Allowed Tools list]
    LoadPersona --> EmbedPrompt[Generate Vector Embedding of prompt]
    
    subgraph Vector Database
        EmbedPrompt --> QueryDB[Search Tool Registry descriptions]
        QueryDB --> RankTools[Rank tools by semantic similarity]
    end
    
    RankTools --> SelectTopN[Filter top N matching tools]
    SelectTopN --> FilterAllowed[Keep only tools on Persona Allowed list]
    FilterAllowed --> InjectSystem[Inject tool schemas into LLM chat options]
    InjectSystem --> StartReAct[Begin ReAct execution loop]
```

---

## 2. HITL Confirmation & State Resume Flow

For sensitive commands (such as firewall modifications or machine isolation), the system halts execution until an analyst manually approves the operation.

```mermaid
sequenceDiagram
    autonumber
    participant Orch as Orchestrator
    participant DB as Redis/Postgres State DB
    participant API as API Gateway
    actor Analyst as SOC Analyst
    participant MCP as SOC MCP Server

    Orch->>Orch: LLM proposes executing containment tool (requires_confirmation=True)
    Orch->>Orch: Catch execution and generate Draft Session logs
    Orch->>DB: Save session state (history, current variables, sandbox metadata)
    Orch-->>API: Return PENDING_APPROVAL status + proposed action details
    API-->>Analyst: Display pending modal: "Allow agent to block IP 198.51.100.1?"
    
    Note over Analyst, API: Analyst reviews logs and inputs decision
    
    alt Approved
        Analyst->>API: POST /api/v1/session/resume {session_id, decision: approve}
        API->>DB: Retrieve saved session state
        DB-->>API: Restore Orchestrator state
        API->>Orch: Resume execution
        Orch->>MCP: Execute containment action tool
        MCP-->>Orch: Return observation: "IP blocked successfully"
        Orch->>Orch: Continue ReAct loop to completion
    else Rejected
        Analyst->>API: POST /api/v1/session/resume {session_id, decision: reject, feedback: "Do not block"}
        API->>DB: Retrieve saved session state
        DB-->>API: Restore Orchestrator state
        API->>Orch: Inject observation: "Action rejected by operator: Do not block"
        Orch->>Orch: Continue ReAct loop (reason about alternative solutions)
    end
    Orch-->>Analyst: Return final structured incident summary
```
