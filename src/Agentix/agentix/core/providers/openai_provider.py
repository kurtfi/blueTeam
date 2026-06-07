from typing import Any

import structlog
from agentic_common.settings import settings
from openai import AsyncOpenAI
from openai.types.chat import ChatCompletionMessageParam

from agentix.core.providers.base import BaseLLMProvider

logger = structlog.get_logger(__name__)


class OpenAIProvider(BaseLLMProvider):
    """Async wrapper around OpenAI Chat Completions."""

    def __init__(
        self,
        model: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> None:
        self._client = AsyncOpenAI(api_key=settings.openai_api_key)
        self.model = model or settings.openai_model
        self.temperature = temperature
        self.max_tokens = max_tokens

    async def chat(
        self,
        messages: list[ChatCompletionMessageParam],
        tools: list[dict] | None = None,
        tool_choice: str | dict = "auto",
    ) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = tool_choice

        logger.debug("llm.request.openai", model=self.model, message_count=len(messages))
        response = await self._client.chat.completions.create(**kwargs)
        choice = response.choices[0].message
        logger.debug("llm.response.openai", finish_reason=response.choices[0].finish_reason)
        return dict(choice.model_dump())
