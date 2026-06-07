import json
from unittest.mock import AsyncMock, patch

import pytest
from agentix.core.providers.ollama_provider import OllamaProvider


@pytest.mark.asyncio
async def test_ollama_chat_tool_call_parsing():
    provider = OllamaProvider(model="test-model")

    with patch("agentix.core.providers.ollama_provider.AsyncClient"):
        mock_client = AsyncMock()
        provider._client = mock_client

        # Mock Ollama response dict
        mock_client.chat.return_value = {
            "message": {
                "role": "assistant",
                "content": "Running tool",
                "tool_calls": [{"function": {"name": "isolate_endpoint", "arguments": {"agent_id": "007"}}}],
            }
        }

        # The messages passed contain a tool_call that should be formatted properly
        # The provider converts string arguments to dicts for Ollama
        messages = [
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "id": "call_123",
                        "type": "function",
                        "function": {"name": "query", "arguments": '{"query": "SELECT * FROM logs"}'},
                    }
                ],
            }
        ]

        response = await provider.chat(messages)

        # Assert Ollama received the converted dictionary arguments
        call_args = mock_client.chat.call_args[1]
        sent_messages = call_args["messages"]
        sent_tc = sent_messages[0]["tool_calls"][0]
        assert isinstance(sent_tc["function"]["arguments"], dict)
        assert sent_tc["function"]["arguments"]["query"] == "SELECT * FROM logs"

        # Assert the response back from Ollama formats tool_call arguments to JSON strings
        assert response["role"] == "assistant"
        tc_out = response["tool_calls"][0]
        assert isinstance(tc_out["function"]["arguments"], str)
        args_out = json.loads(tc_out["function"]["arguments"])
        assert args_out["agent_id"] == "007"
