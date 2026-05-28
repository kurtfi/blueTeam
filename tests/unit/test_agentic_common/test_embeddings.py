import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from agentic_common.embeddings import OllamaEmbeddingProvider, OpenAIEmbeddingProvider

@pytest.mark.asyncio
async def test_ollama_embed_query():
    with patch("agentic_common.embeddings.OllamaAsyncClient") as MockClient:
        mock_client_instance = AsyncMock()
        MockClient.return_value = mock_client_instance
        
        # Mock response format: resp.embedding
        mock_resp = MagicMock()
        mock_resp.embedding = [0.1, 0.2, 0.3]
        mock_client_instance.embeddings.return_value = mock_resp
        
        provider = OllamaEmbeddingProvider(model="test-model")
        res = await provider.embed_query("hello")
        
        assert res == [0.1, 0.2, 0.3]
        mock_client_instance.embeddings.assert_called_once_with(model="test-model", prompt="hello")

@pytest.mark.asyncio
async def test_openai_embed_query():
    with patch("agentic_common.embeddings.AsyncOpenAI") as MockClient:
        mock_client_instance = AsyncMock()
        MockClient.return_value = mock_client_instance
        
        mock_resp = MagicMock()
        mock_item = MagicMock()
        mock_item.embedding = [0.4, 0.5, 0.6]
        mock_resp.data = [mock_item]
        
        mock_client_instance.embeddings.create = AsyncMock(return_value=mock_resp)
        
        provider = OpenAIEmbeddingProvider(model="text-embedding-3-small")
        res = await provider.embed_query("hello")
        
        assert res == [0.4, 0.5, 0.6]
        mock_client_instance.embeddings.create.assert_called_once_with(input=["hello"], model="text-embedding-3-small")
