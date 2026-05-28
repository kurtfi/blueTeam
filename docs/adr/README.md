# Architecture Decision Records (ADRs)

This directory contains records of critical technical decisions made during the design and development of the BlueTeam / Agentix platform. We use Architecture Decision Records (ADRs) to document why decisions were made, what context led to them, and what trade-offs were accepted.

We follow the MADR (Markdown Architecture Decision Record) format.

## ADR Index

| ID | Title | Date | Status | Summary |
|---|---|---|---|---|
| [ADR-0001](file:///Users/firatkurt/Documents/Repos/blueTeam/docs/adr/0001-tool-first-architecture.md) | **Tool-First Architecture** | 2026-05-28 | Approved | Define LLM as a reasoning agent that interacts through execution tools. |
| [ADR-0002](file:///Users/firatkurt/Documents/Repos/blueTeam/docs/adr/0002-mcp-decoupling.md) | **Model Context Protocol Decoupling** | 2026-05-28 | Approved | Decouple SOC platform credentials and API connections into standalone FastMCP microservices. |
| [ADR-0003](file:///Users/firatkurt/Documents/Repos/blueTeam/docs/adr/0003-react-loop-orchestration.md) | **ReAct Loop Orchestration** | 2026-05-28 | Approved | Orchestrate reasoning patterns via a sequential Think-Act-Observe loop. |
| [ADR-0004](file:///Users/firatkurt/Documents/Repos/blueTeam/docs/adr/0004-multi-provider-llm.md) | **Multi-Provider LLM Integration** | 2026-05-28 | Approved | Prevent vendor lock-in via an Abstract Factory + Strategy pattern for LLMs. |
| [ADR-0005](file:///Users/firatkurt/Documents/Repos/blueTeam/docs/adr/0005-session-workspace-sandbox.md) | **Session Workspace Sandboxing** | 2026-05-28 | Approved | Ensure strict workspace security and path traversal protection for agent sessions. |
| [ADR-0006](file:///Users/firatkurt/Documents/Repos/blueTeam/docs/adr/0006-llm-based-agent-routing.md) | **LLM-Based Agent Intent Routing** | 2026-05-28 | Approved | Migrate from semantic embedding similarity to lightweight LLM classifier for agent routing. |
| [ADR-0007](file:///Users/firatkurt/Documents/Repos/blueTeam/docs/adr/0007-native-rag-injection.md) | **Native System Prompt RAG Injection** | 2026-05-28 | Approved | Inject domain knowledge dynamically into system prompt instead of running manual RAG tool calls. |
| [ADR-0008](file:///Users/firatkurt/Documents/Repos/blueTeam/docs/adr/0008-hitl-confirmation-flow.md) | **Human-In-The-Loop Confirmation Flow** | 2026-05-28 | Approved | Gate destructive actions with user approval using draft histories. |

## Creating New ADRs

To propose or document a new architectural decision, copy the [template.md](file:///Users/firatkurt/Documents/Repos/blueTeam/docs/adr/template.md) file, name it sequentially, e.g. `0009-your-decision-title.md`, fill in the sections, and add it to the index above.
