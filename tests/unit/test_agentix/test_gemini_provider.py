import pytest
import json
from unittest.mock import AsyncMock, patch, MagicMock
from agentix.core.providers.gemini_provider import GeminiProvider

@pytest.mark.asyncio
@patch.dict("os.environ", {"GEMINI_API_KEY": "fake_key"})
async def test_gemini_chat_parsing():
    with patch("agentix.core.providers.gemini_provider.genai.Client") as MockClient:
        mock_client = MagicMock()
        MockClient.return_value = mock_client
        mock_client.aio.models.generate_content = AsyncMock()
        
        provider = GeminiProvider(model="gemini-1.5-flash")
        
        # Mock Gemini response
        mock_resp = MagicMock()
        
        # Mock function call inside Gemini response
        mock_fc = MagicMock()
        mock_fc.name = "get_weather"
        mock_fc.args = {"location": "London"}
        
        mock_part = MagicMock()
        mock_part.text = "Hello there"
        mock_part.function_call = mock_fc
        
        mock_resp.candidates = [MagicMock(content=MagicMock(parts=[mock_part]))]
        mock_client.aio.models.generate_content.return_value = mock_resp
        
        messages = [{"role": "user", "content": "What is the weather?"}]
        response = await provider.chat(messages)
        
        assert response["role"] == "assistant"
        assert response["content"] == "Hello there"
        
        assert response["tool_calls"] is not None
        tc = response["tool_calls"][0]
        assert tc["type"] == "function"
        assert tc["function"]["name"] == "get_weather"
        
        # Verify arguments are a JSON string, as the orchestrator expects
        args = json.loads(tc["function"]["arguments"])
        assert args["location"] == "London"
