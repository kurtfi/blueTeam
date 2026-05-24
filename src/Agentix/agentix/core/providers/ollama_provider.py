import structlog
import json
import uuid
from typing import Any
from ollama import AsyncClient
from agentic_common.settings import settings
from agentix.core.providers.base import BaseLLMProvider
from openai.types.chat import ChatCompletionMessageParam

logger = structlog.get_logger(__name__)

class OllamaProvider(BaseLLMProvider):
    """Async wrapper around Ollama."""

    def __init__(
        self,
        model: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> None:
        self._client = AsyncClient(host=settings.ollama_base_url)
        self.model = model or settings.ollama_model
        # Note: temperature and max_tokens mapping can be added via options dict
        self.options = {
            "temperature": temperature,
            "num_predict": max_tokens,
        }

    async def chat(
        self,
        messages: list[ChatCompletionMessageParam],
        tools: list[dict] | None = None,
        tool_choice: str | dict = "auto",
    ) -> dict[str, Any]:
        
        # Convert messages if they contain system prompts in a weird state, usually ollama is fine
        # We also need to map tool_calls.function.arguments back to dict for the Ollama client
        formatted_messages = []
        for msg in messages:
            msg_copy = dict(msg) # type: ignore
            if msg_copy.get("role") == "assistant" and msg_copy.get("tool_calls"):
                formatted_tool_calls = []
                for tc in msg_copy["tool_calls"]:
                    tc_copy = dict(tc) # type: ignore
                    if "function" in tc_copy and "arguments" in tc_copy["function"]:
                        func_copy = dict(tc_copy["function"])
                        args = func_copy.get("arguments")
                        if isinstance(args, str):
                            try:
                                func_copy["arguments"] = json.loads(args)
                            except json.JSONDecodeError:
                                pass
                        tc_copy["function"] = func_copy
                    formatted_tool_calls.append(tc_copy)
                msg_copy["tool_calls"] = formatted_tool_calls
            formatted_messages.append(msg_copy)

        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": formatted_messages,
            "options": self.options,
            # Disable thinking mode (gemma4 etc.) so the actual response
            # goes into 'content' rather than a separate 'thinking' field.
            "think": False,
        }
        
        # Ollama supports the OpenAI tool schema natively
        if tools:
            kwargs["tools"] = tools

        logger.debug("llm.request.ollama", model=self.model, message_count=len(messages))
        response = await self._client.chat(**kwargs)
        
        # We need to adapt the Ollama response to look exactly like the OpenAI dict format
        message = response.get("message", {})
        
        # Ensure tool_calls match OpenAI structure
        tool_calls = message.get("tool_calls") or []
        formatted_tool_calls = []
        for tc in tool_calls:
            # Ollama function arguments are usually dicts, but Orchestrator expects JSON strings!
            function_data = tc.get("function", {})
            args = function_data.get("arguments", {})
            if isinstance(args, dict):
                args_str = json.dumps(args)
            else:
                args_str = str(args)
                
            formatted_tc = {
                "id": f"call_{uuid.uuid4().hex[:12]}",  # Ollama doesn't always provide an ID
                "type": "function",
                "function": {
                    "name": function_data.get("name", ""),
                    "arguments": args_str
                }
            }
            formatted_tool_calls.append(formatted_tc)
            
        return {
            "role": message.get("role", "assistant"),
            "content": message.get("content", ""),
            "tool_calls": formatted_tool_calls if formatted_tool_calls else None
        }
