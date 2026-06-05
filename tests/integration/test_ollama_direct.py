import json
import os

import pytest
from agentix.core.providers.ollama_provider import OllamaProvider

pytestmark = pytest.mark.skipif(
    not os.getenv("OLLAMA_BASE_URL"), 
    reason="OLLAMA_BASE_URL is not configured"
)

@pytest.mark.asyncio
async def test_ollama_chat_completion():
    provider = OllamaProvider(model="qwen3.5:9b")
    
    tools = [
        {
            "type": "function",
            "function": {
                "name": "find_playbook_for_alert",
                "description": "Find appropriate playbooks for a given MITRE technique ID.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "mitre_ids": {
                            "type": "array",
                            "items": {"type": "string"}
                        }
                    },
                    "required": ["mitre_ids"]
                }
            }
        }
    ]

    messages = [
        {"role": "system", "content": "You are a SOC Analyst."},
        {"role": "user", "content": "T1003.008 alert came in. Find the playbook."}
    ]

    # Test that Ollama provider returns a valid response
    response = await provider.chat(messages, tools=tools)
    
    assert "role" in response
    assert response["role"] == "assistant"
    # Content or tool_calls must be present
    assert response.get("content") or response.get("tool_calls")
    
    # If tool calls are made, verify structure
    if response.get("tool_calls"):
        tc = response["tool_calls"][0]
        assert tc["type"] == "function"
        assert "name" in tc["function"]
        assert "arguments" in tc["function"]
        
        # Test serialization of arguments
        args = json.loads(tc["function"]["arguments"])
        assert isinstance(args, dict)
