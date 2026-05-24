from abc import ABC, abstractmethod
from typing import Any

from openai.types.chat import ChatCompletionMessageParam


class BaseLLMProvider(ABC):
    """Abstract base class for LLM providers."""

    @abstractmethod
    async def chat(
        self,
        messages: list[ChatCompletionMessageParam],
        tools: list[dict] | None = None,
        tool_choice: str | dict = "auto",
    ) -> dict[str, Any]:
        """
        Send a chat request to the LLM.

        Args:
            messages: Full conversation history in OpenAI format.
            tools:    Optional list of tool schemas for function-calling.
            tool_choice: How the model should pick tools ("auto", "none", or
                         a specific tool dict).

        Returns:
            The raw message dict (OpenAI format equivalent) from the first choice.
        """
        pass
