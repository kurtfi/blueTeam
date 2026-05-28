# LLM-Based Agent Intent Routing

* Status: accepted
* Deciders: Architect, Lead AI Engineer
* Date: 2026-05-28

## Context and Problem Statement

When a user submits an investigation request (e.g. "I see a spike in login failures, check if it's a brute force attack"), we must route it to the appropriate specialist agent persona (e.g., `soc_analyst`, `threat_intel`, `firewall_admin`).
Previously, we used a vector embedding engine to compute cosine similarity between the user request and descriptions of each agent persona. However, semantic similarity failed when:
1. Requests were in different languages (e.g., Turkish or German prompts routed incorrectly because they didn't match English descriptions).
2. Intent was complex and required nuance that simple keyword/vector closeness could not identify.
We need a robust routing system that works across languages and captures explicit intent.

## Decision Drivers

* High routing accuracy across multiple languages (TR/EN).
* Low latency (routing must happen quickly before starting the ReAct loop).
* Support for a dynamic lists of agent personas.

## Considered Options

1. **Cosine Similarity Embedding Routing**: Compare text embeddings of the prompt against persona files.
2. **LLM-Based Intent Classification**: Send a small JSON-structured prompt containing the list of available personas to a lightweight LLM model and ask it to categorize the request.

## Decision Outcome

Chosen option: **Option 2 (LLM-Based Intent Classification)**. Implemented in `src/Agentix/agentix/agents/router.py`, the system calls a fast, small model (like GPT-4o-mini or Gemma) to analyze the user request and select the matching agent name from a list of schemas. The latency is small (~200ms) but the routing accuracy and multi-language understanding are vastly superior.

### Positive Consequences

* **Multi-language Support**: The LLM understands Turkish prompts (e.g., "giriş denemelerini kontrol et") and successfully maps them to the correct English-configured `soc_analyst` or `log_analyst` personas.
* **Complex Reasoning**: The router can handle ambiguous requests by falling back to a default triage agent when no specific agent is a high-confidence match.

### Negative Consequences

* **API Call Overhead**: Adds one extra LLM API call before the actual investigation loop begins, adding slightly to cost and latency. We mitigate this by caching routing decisions for identical queries.
