# Multi-Provider LLM Integration

* Status: accepted
* Deciders: Architect, Lead AI Engineer
* Date: 2026-05-28

## Context and Problem Statement

Different LLM providers (OpenAI, Google Gemini, Ollama, Anthropic) have separate SDKs, pricing, token limits, and performance characteristics. In security operations, organizations may prefer local offline LLMs (via Ollama/vLLM) to keep log files in-house, while others might prefer powerful cloud APIs like OpenAI's GPT-4o for complex forensics. Hardcoding the orchestrator to a single provider prevents flexibilty and couples code to a vendor.

## Decision Drivers

* Avoid vendor lock-in.
* Enable hybrid deployments (e.g. cloud models for routing, local models for sensitive log analysis).
* Ensure clean code abstraction for chat completions and structured outputs.

## Considered Options

1. **Provider-Specific Code Blocks**: Use `if/else` checks throughout the orchestrator code to invoke different SDKs depending on configuration.
2. **Strategy + Abstract Factory Pattern**: Define a unified `BaseLLMClient` interface. Implement specific providers (`OpenAIClient`, `GeminiClient`, `OllamaClient`) extending this base class. Instantiate them via an `LLMFactory`.

## Decision Outcome

Chosen option: **Option 2 (Strategy + Abstract Factory Pattern)**. Implemented in `src/Agentix/agentix/core/llm.py`, this allows the orchestrator to invoke completion calls without knowing which model is executing underneath. The client choice is configured purely via environment variables (`OPENAI_API_KEY`, `GEMINI_API_KEY`, or `OLLAMA_HOST`).

### Positive Consequences

* **Clean Orchestrator Code**: The core orchestrator only deals with a single API interface (`BaseLLMClient.generate_completion`).
* **Easy Extension**: Adding a new provider (e.g. Anthropic or Mistral) simply requires subclassing `BaseLLMClient` and registering it in `LLMFactory`.
* **Testing & Mocks**: We can mock LLM responses during tests easily by injecting a dummy/test implementation of `BaseLLMClient`.

### Negative Consequences

* **Feature Parity Challenges**: Different LLMs support different features. For example, structured outputs (JSON schema mode) or parallel tool calling work natively on GPT-4o but might require manual parser implementations on smaller local models.
