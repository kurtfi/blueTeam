"""
Abstract Factory and Client wrapper for routing requests to 
various LLM providers (Ollama, OpenAI, Gemini).
"""
from __future__ import annotations

import hashlib
import json
import structlog
from typing import Any

from agentic_common.settings import settings
from agentix.core.providers.base import BaseLLMProvider
from agentix.core.providers.openai_provider import OpenAIProvider
from agentix.core.providers.gemini_provider import GeminiProvider
from agentix.core.providers.ollama_provider import OllamaProvider
from openai.types.chat import ChatCompletionMessageParam

logger = structlog.get_logger(__name__)


class LLMProviderFactory:
    """Factory to instantiate the appropriate LLM provider."""
    
    @staticmethod
    def create_provider(
        provider_name: str | None = None,
        model: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> BaseLLMProvider:
        provider = provider_name or settings.agentix_llm_provider
        
        if provider == "openai":
            return OpenAIProvider(model, temperature, max_tokens)
        elif provider == "gemini":
            return GeminiProvider(model, temperature, max_tokens)
        elif provider == "ollama":
            return OllamaProvider(model, temperature, max_tokens)
        else:
            logger.warning("llm.factory.unknown_provider", provider=provider, fallback="ollama")
            return OllamaProvider(model, temperature, max_tokens)


class LLMClient:
    """Client wrapper delegating to the selected LLM Provider Strategy."""

    def __init__(
        self,
        model: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
        cache_enabled: bool = True,
    ) -> None:
        self._provider = LLMProviderFactory.create_provider(
            model=model,
            temperature=temperature,
            max_tokens=max_tokens
        )
        self.model = getattr(self._provider, "model", model) 
        self.temperature = temperature
        self.cache_enabled = cache_enabled
        self._cache: dict[str, dict[str, Any]] = {}

    def _get_cache_key(
        self,
        messages: list[ChatCompletionMessageParam],
        tools: list[dict] | None = None,
        tool_choice: str | dict = "auto",
    ) -> str:
        """Generate a deterministic hash for the request."""
        request_obj = {
            "model": self.model,
            "messages": messages,
            "tools": tools,
            "tool_choice": tool_choice,
            "temperature": self.temperature
        }
        # Deep serialize to handle the complex types in messages/tools
        raw = json.dumps(request_obj, sort_keys=True, default=str)
        return hashlib.sha256(raw.encode()).hexdigest()

    async def chat(
        self,
        messages: list[ChatCompletionMessageParam],
        tools: list[dict] | None = None,
        tool_choice: str | dict = "auto",
    ) -> dict[str, Any]:
        """
        Send a chat request to the active LLM provider.
        Supports response caching for deterministic (temperature=0) requests.
        """
        # Only cache deterministic requests
        if self.cache_enabled and self.temperature == 0:
            key = self._get_cache_key(messages, tools, tool_choice)
            if key in self._cache:
                logger.debug("llm.cache.hit", model=self.model)
                return self._cache[key]

        response = await self._provider.chat(messages, tools, tool_choice)

        if self.cache_enabled and self.temperature == 0:
            key = self._get_cache_key(messages, tools, tool_choice)
            self._cache[key] = response
            logger.debug("llm.cache.miss", model=self.model)

        return response
