# BlueTeam / Agentix 🛡️🤖

[![CI](https://github.com/firatkurt/blueTeam/actions/workflows/ci.yml/badge.svg)](https://github.com/firatkurt/blueTeam/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.12+](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://www.python.org/)
[![Docker: V2](https://img.shields.io/badge/Docker-Compose_V2-blue.svg)](https://www.docker.com/)

**BlueTeam / Agentix** is a state-of-the-art modular platform for AI-driven Security Operations (SecOps). It orchestrates autonomous AI agents to perform security triage, incident investigation, threat intelligence enrichment, and response playbooks in a sandboxed, security-first environment. 

Designed for DevSecOps engineers, security researchers, and educators, it bridges the gap between modern LLM agentic architectures and real-world Security Operations Centers (SOCs).

---

## 🔍 Architecture at a Glance

The platform utilizes a **Modular Monorepo** structure built with `uv` workspaces, decoupling the AI orchestration core (`Agentix`) from security integrations (`TriageCore`) and containerized services (`Infrastructure`).

```mermaid
graph TD
    User([SOC Analyst / API Client]) -->|Requests| Gateway[API Gateway / Gateway Service]
    
    subgraph Agentix Core [Agentix Orchestration Engine]
        Gateway -->|Internal API| Orchestrator[Agentix Orchestrator]
        Orchestrator -->|Dynamic Selection| PersonaManager[Agent Persona System]
        Orchestrator -->|Augment System Prompt| RAG[Native RAG System]
        Orchestrator -->|ReAct Loop| LLMClient[LLM Strategy / Factory]
        Orchestrator -->|Secure Execution| Sandbox[Session Workspace Sandbox]
    end

    LLMClient -->|API Calls| LLMProviders[OpenAI / Gemini / Ollama]

    subgraph Tool Integration Layer
        Orchestrator -->|Model Context Protocol SSE| TriageCore[SOC FastMCP Server]
        TriageCore -->|API| Wazuh[Wazuh SIEM / EDR]
        TriageCore -->|API| TheHive[TheHive Case Mgmt]
        TriageCore -->|API| Cortex[Cortex Enrichment]
    end

    subgraph Infrastructure [Docker-Compose Services]
        Wazuh
        TheHive
        Cortex
    end
```

---

## 🧠 Key Concepts

| Concept | Description |
|:---|:---|
| **ReAct Loop** | A Think ➔ Act ➔ Observe ➔ Answer reasoning loop where the agent decides what to do, runs tools, observes the output, and reasons again. |
| **Model Context Protocol (MCP)** | Decouples tools from the LLM orchestrator. Tools run inside containerized FastMCP servers, protecting main credentials and restricting network access. |
| **Dynamic Tool Selection** | Uses semantic similarity embeddings to load only relevant tools into the agent's context, optimizing token usage and improving model accuracy. |
| **Session Sandbox** | Each agent session runs in an isolated workspace with path-traversal protection and restricted directory access to secure system execution. |
| **HITL Confirmation** | Human-In-The-Loop flow requiring developer approval for destructive actions (e.g. firewall blocking, account isolation). |
| **Agent Personas** | Configurable YAML personalities (e.g., `soc_analyst`, `threat_intel`) defining prompt logic, roles, and allowed tools. |

---

## 📂 Project Structure

```
blueTeam/
├── .github/workflows/         # CI/CD pipelines (linter, mypy, pytest)
├── docs/                      # Architectural Decision Records (ADRs) & Detailed Guides
│   ├── adr/                   # Architecture Decision Records (MADR format)
│   ├── architecture/          # System, data flow, and deployment diagrams
│   ├── guides/                # Getting started, adding tools, agents, and integrations
│   └── glossary.md            # Technical terms reference
├── Infrastructure/            # Docker Compose setups for Wazuh, TheHive, and Cortex
├── src/
│   ├── Agentix/               # The core AI Agent Orchestrator & API Gateway
│   ├── TriageCore/                # Model Context Protocol (MCP) server for SOC integrations
│   ├── AgenticCommon/         # Shared libraries (LLM clients, sandboxing utilities)
│   └── IntegrationTests/      # End-to-end and connectivity testing scripts
├── .env.example               # Unified environment variables template
├── LICENSE                    # MIT License
└── SECURITY.md                # Security policy and disclosure guide
```

---

## 🛠️ Prerequisites

- **Python**: 3.12 or higher
- **Package Manager**: [uv](https://github.com/astral-sh/uv) (recommended)
- **Docker**: Docker Engine & Docker Compose V2
- **API Keys**: At least one of the following:
  - OpenAI API Key (for GPT models)
  - Gemini API Key (for Google models)
  - Local [Ollama](https://ollama.com/) instance (for running models locally)

---

## 🚀 Quick Start (5 Steps)

Follow these steps to deploy and test the entire platform on your local machine:

### Step 1: Clone and Configure Environment
Clone the repository and copy the unified configuration file:
```bash
git clone https://github.com/firatkurt/blueTeam.git
cd blueTeam
cp .env.example .env
```
Edit the `.env` file to add your `OPENAI_API_KEY` or configure your LLM provider.

### Step 2: Set Up Python Workspace
Sync the packages and developer tools using `uv`:
```bash
uv sync --all-extras --dev
```

### Step 3: Launch Security Infrastructure
Spin up Wazuh, TheHive, and Cortex via Docker Compose:
```bash
cd Infrastructure
docker compose up -d
```
*Note: It may take a couple of minutes for all security containers to fully initialize.*

### Step 4: Run the MCP Servers & Core Agentix API
Open a new terminal window in the root directory and start the orchestration core:
```bash
# Set your PYTHONPATH and start Agentix Gateway & Orchestrator
cd src/Agentix
uv run uvicorn agentix.api.app:app --host 0.0.0.0 --port 8000 --reload
```

### Step 5: Run a Sample Investigation
Ask the agent to investigate an alert by executing a quick cURL command:
```bash
curl -X POST http://localhost:8000/api/v1/investigate \
  -H "Authorization: Bearer dev-internal-key-change-me-in-production" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "soc_analyst",
    "prompt": "Investigate alert with ID wazuh-alert-8923 and summarize the results."
  }'
```

---

## 🔄 How It Works (Sequence Diagram)

```mermaid
sequenceDiagram
    autonumber
    actor User as SOC Analyst / Client
    participant Gateway as API Gateway
    participant Orch as Orchestrator
    participant Sandbox as Session Sandbox
    participant MCP as SOC MCP Server (FastMCP)
    participant LLM as LLM Provider (OpenAI/Ollama)

    User->>Gateway: POST /api/v1/investigate
    Gateway->>Orch: Start session & parse agent rules
    Orch->>Sandbox: Initialize isolated workspace directory
    loop ReAct Orchestration Loop
        Orch->>LLM: Think: What is the current status?
        LLM-->>Orch: Action: Read Wazuh logs (Tool call)
        Orch->>MCP: Request tool execution (SSE/MCP)
        MCP->>Sandbox: Execute tool in sandboxed context
        Sandbox-->>MCP: Tool execution result
        MCP-->>Orch: Return observation data
        Orch->>LLM: Observe: Here are the logs. What next?
        LLM-->>Orch: Think: Investigate IP. Action: AbuseIPDB
    end
    Orch->>User: Return final structured incident report
```

---

## 🎓 Educational Focus

This repository is tailored for learning. If you are using this for training or educational purposes:
- Check out [docs/guides/getting-started.md](file:///Users/firatkurt/Documents/Repos/blueTeam/docs/guides/getting-started.md) for a detailed walkthrough of the environment setup.
- Read through the [ADRs (Architecture Decision Records)](file:///Users/firatkurt/Documents/Repos/blueTeam/docs/adr/README.md) to understand *why* we chose specific agent patterns over others.
- Use [docs/guides/adding-a-tool.md](file:///Users/firatkurt/Documents/Repos/blueTeam/docs/guides/adding-a-tool.md) as a tutorial task to build your own security agent tooling.

---

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](file:///Users/firatkurt/Documents/Repos/blueTeam/CONTRIBUTING.md) to understand our coding standards (ruff + mypy), commit guidelines, and branching workflow.

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](file:///Users/firatkurt/Documents/Repos/blueTeam/LICENSE) file for details.