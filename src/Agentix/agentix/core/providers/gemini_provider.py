import json
import uuid
from typing import Any
import structlog
from google import genai
from google.genai import types
from agentic_common.settings import settings
from agentix.core.providers.base import BaseLLMProvider
from openai.types.chat import ChatCompletionMessageParam

logger = structlog.get_logger(__name__)

class GeminiProvider(BaseLLMProvider):
    """Async wrapper around Google Gemini APIs using google-genai."""

    def __init__(
        self,
        model: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> None:
        self._client = genai.Client(api_key=settings.gemini_api_key)
        self.model = model or settings.gemini_model
        # Note: temperature and max_tokens mapping
        self.temperature = temperature
        self.max_tokens = max_tokens

    async def chat(
        self,
        messages: list[ChatCompletionMessageParam],
        tools: list[dict] | None = None,
        tool_choice: str | dict = "auto",
    ) -> dict[str, Any]:
        
        # 1. Map OpenAI messages to Gemini formatted contents
        contents = []
        system_instruction = None
        
        for msg in messages:
            role = msg.get("role")
            content = msg.get("content", "")
            
            if role == "system":
                # System prompt needs to be passed via config in Gemini
                system_instruction = content
                continue
                
            if role == "assistant":
                gemini_role = "model"
                parts = []
                if content:
                    parts.append({"text": content})
                if msg.get("tool_calls"):
                    for tc in msg["tool_calls"]:
                        try:
                            args = tc["function"]["arguments"]
                            if isinstance(args, str):
                                args = json.loads(args)
                        except Exception:
                            args = {}
                        parts.append({
                            "function_call": {
                                "name": tc["function"]["name"],
                                "args": args
                            }
                        })
                contents.append({"role": gemini_role, "parts": parts})
                continue
                
            if role == "tool":
                # User's tool response
                try: # Handle dict string representation
                    content_json = json.loads(content) if isinstance(content, str) else content
                except Exception:
                    content_json = {"result": content}
                    
                contents.append({
                    "role": "user",
                    "parts": [{
                        "function_response": {
                            "name": msg.get("tool_call_id", "unknown_tool"),
                            "response": content_json
                        }
                    }]
                })
                continue
                
            # Default user messages
            contents.append({"role": "user", "parts": [{"text": str(content)}]})

        # 2. Map OpenAI Tools to Gemini format (they support OpenAPI standard json schemas mostly)
        gemini_tools = []
        if tools:
            for t in tools:
                if t.get("type") == "function":
                    func_def = t["function"]
                    gemini_tools.append({
                        "function_declarations": [{
                            "name": func_def["name"],
                            "description": func_def.get("description", ""),
                            # Gemini uses parameters directly like OpenAI
                            "parameters": func_def.get("parameters", {})
                        }]
                    })
                    
        config_kwargs = {
            "temperature": self.temperature,
            "max_output_tokens": self.max_tokens,
        }
        
        if system_instruction:
            config_kwargs["system_instruction"] = system_instruction
            
        if gemini_tools:
            config_kwargs["tools"] = gemini_tools
            # Gemini typically ignores 'auto' parameter if not explicitly set correctly, defaults to auto when tools are passed
            # config_kwargs["tool_config"] = {"function_calling_config": {"mode": "AUTO"}} # Example mapping if needed

        try:
            logger.debug("llm.request.gemini", model=self.model, message_count=len(messages))
            
            # Using async generation
            response = await self._client.aio.models.generate_content(
                model=self.model,
                contents=contents,
                config=types.GenerateContentConfig(**config_kwargs)
            )
            
            logger.debug("llm.response.gemini", candidates=len(response.candidates) if response.candidates else 0)
            
            # 3. Re-map response to OpenAI format
            message_content = ""
            formatted_tool_calls = []
            
            if response.candidates and len(response.candidates) > 0:
                candidate = response.candidates[0]
                if candidate.content and candidate.content.parts:
                    for part in candidate.content.parts:
                        if hasattr(part, "text") and part.text:
                            message_content += part.text
                        if hasattr(part, "function_call") and part.function_call:
                            # Remap function args to JSON string
                            fc = part.function_call
                            args_dict = {}
                            if hasattr(fc, "args") and fc.args:
                                args_dict = dict(fc.args) # type: ignore
                            
                            formatted_tc = {
                                "id": f"call_{uuid.uuid4().hex[:12]}",
                                "type": "function",
                                "function": {
                                    "name": fc.name or "",
                                    "arguments": json.dumps(args_dict)
                                }
                            }
                            formatted_tool_calls.append(formatted_tc)
            
            return {
                "role": "assistant",
                "content": message_content,
                "tool_calls": formatted_tool_calls if formatted_tool_calls else None
            }
            
        except Exception as e:
            logger.error("gemini.api_error", error=str(e))
            raise
