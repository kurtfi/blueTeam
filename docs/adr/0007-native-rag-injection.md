# Native System Prompt RAG Injection

* Status: accepted
* Deciders: Architect, Lead AI Engineer
* Date: 2026-05-28

## Context and Problem Statement

Security agents need access to organizational policies, runbooks, playbook definitions, and architecture data to make correct decisions. For instance, when dealing with an alert, the agent must know the severity level guidelines or IP whitelists.
We can retrieve this using Retrieval-Augmented Generation (RAG). However, exposing RAG as a tool (e.g. `query_knowledge_base`) means the agent must waste reasoning steps deciding to call the tool, crafting a search query, waiting for the results, and processing them. This increases latency, token costs, and leaves room for the model to forget to query the knowledge base at the beginning of an investigation.

## Decision Drivers

* Minimize the number of reasoning steps in the ReAct loop.
* Guarantee that domain-specific context is *always* available to the model.
* Keep context token consumption optimized.

## Considered Options

1. **RAG-as-a-Tool**: Expose the vector store lookup as a standard tool callable by the agent during the loop.
2. **Native System Prompt Injection**: Perform a quick semantic search on the user's initial query *before* the ReAct loop starts. Inject the top retrieved runbooks and context chunks directly into the orchestrator's system prompt.

## Decision Outcome

Chosen option: **Option 2 (Native System Prompt Injection)**. The orchestrator fetches relevant playbook files from the vector store or local files matching the incident category and appends them under a `[REFERENCE CONTEXT]` header in the system prompt. This ensures the agent is fully primed with operational policies before it takes its first thought step.

### Positive Consequences

* **Reduced Iterations**: Eliminates 1-2 tool-call steps per session, speeding up investigations and saving tokens.
* **Higher Reliability**: The agent cannot "forget" to check the playbook because the playbook is already injected into its primary instructions.

### Negative Consequences

* **Prompt Bloat**: Injecting large runbooks takes up system prompt tokens, leaving less room for tool output history. We mitigate this by using strict token budget slicing (e.g., maximum 2000 tokens for RAG context).
