"""
ContextManager — Tiered Context Strategy & Token Counting.

Prevents context window overflow by truncating or summarizing message history.
"""
from __future__ import annotations

from typing import Any

import structlog
import tiktoken

logger = structlog.get_logger(__name__)

class ContextManager:
    """
    Manages the message history, ensuring it fits within LLM token limits.
    """
    def __init__(self, model: str = "gpt-4o", max_tokens: int = 128000, buffer_tokens: int = 4000) -> None:
        self.model = model
        self.max_tokens = max_tokens
        self.buffer_tokens = buffer_tokens
        
        try:
            self.encoding = tiktoken.encoding_for_model(model)
        except KeyError:
            # Fallback to cl100k_base for unknown models (Ollama/custom)
            self.encoding = tiktoken.get_encoding("cl100k_base")
            logger.warning("context.tiktoken.model_not_found", model=model, fallback="cl100k_base")

    def count_tokens(self, messages: list[dict[str, Any]]) -> int:
        """
        Approximate token count for conversational messages.
        """
        num_tokens = 0
        for message in messages:
            # Approx 4 tokens for metadata/headers
            num_tokens += 4
            for key, value in message.items():
                if isinstance(value, str):
                    num_tokens += len(self.encoding.encode(value))
                if key == "name":
                    num_tokens += -1  # Adjust for sender name if present
        num_tokens += 2  # Every response starts with assistant prefix
        return num_tokens

    def manage(self, messages: list[dict[str, Any]], limit: int | None = None) -> list[dict[str, Any]]:
        """
        Truncate history if it exceeds the limit.
        Always preserves the system prompt (if first).
        """
        target_limit = limit or (self.max_tokens - self.buffer_tokens)
        
        # Keep system prompt if it's there
        system_prompt = None
        current_messages = messages[:]
        if current_messages and current_messages[0].get("role") == "system":
            system_prompt = current_messages.pop(0)

        while self.count_tokens([system_prompt] + current_messages if system_prompt else current_messages) > target_limit:
            if len(current_messages) <= 1:
                # Can't truncate more without losing the user's current message
                logger.warning("context.manage.cannot_truncate_further")
                break
            
            # Truncate the oldest non-system message
            removed = current_messages.pop(0)
            logger.debug("context.manage.truncated_oldest", role=removed.get("role"))

        return [system_prompt] + current_messages if system_prompt else current_messages
