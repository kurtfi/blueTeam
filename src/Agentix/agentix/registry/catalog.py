"""
ToolCatalog — dynamic tool registry and intent-based selection.

Tools are registered at startup and selected per-request based on
semantic similarity between the user's message and each tool's description.
"""

from __future__ import annotations

import json
import math
import re
from typing import TYPE_CHECKING, Any

import redis.asyncio as aioredis
import structlog
from agentic_common.base_tool import BaseTool
from agentic_common.embeddings import EmbeddingFactory
from agentic_common.settings import settings

if TYPE_CHECKING:
    pass

logger = structlog.get_logger(__name__)

_EMBEDDING_CACHE_KEY = "agentix:tool_embeddings"
_EMBEDDING_CACHE_TTL = 86400  # 24 hours — embeddings don't change without a deploy


class ToolCatalog:
    """
    Central registry for all Agentix tools.

    Responsibilities
    ----------------
    1. **Registration** — store tool instances keyed by name.
    2. **Dynamic Selection** — given a user message, return only the tools
       whose description matches the detected intent.  The default strategy
       is keyword/heuristic matching; swap :meth:`_score` for an embedding-
       based approach in production.

    Usage
    -----
    .. code-block:: python

        catalog = ToolCatalog()
        catalog.register(FileManager())
        catalog.register(RAGSearch())

        # At request time:
        tools = await catalog.select("List all files in /tmp")
        # → [FileManager instance]
    """

    def __init__(self) -> None:
        self._tools: dict[str, BaseTool] = {}
        # Local in-process cache for hot path (avoids Redis round-trip on repeated calls)
        self._local_embeddings: dict[str, list[float]] = {}
        self._embed_provider = EmbeddingFactory.create_provider()
        # Redis client — shared across all ToolCatalog instances in the same process
        self._redis: aioredis.Redis = aioredis.from_url(settings.redis_url, decode_responses=True)
        self.cached_playbooks: str | None = None

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, tool: BaseTool) -> None:
        """Add a tool to the registry."""
        if tool.name in self._tools:
            logger.warning("catalog.register.duplicate", tool=tool.name)
        self._tools[tool.name] = tool
        logger.debug("catalog.register", tool=tool.name, category=tool.category)

    def register_many(self, tools: list[BaseTool]) -> None:
        for t in tools:
            self.register(t)

    async def register_mcp_client(self, client: Any) -> None:
        """
        Dynamically register all tools from a FastMCP or standard MCP client
        into the Agentix ToolCatalog using the MCPToolAdapter.
        """
        from agentix.tools.mcp_adapter import MCPToolAdapter

        result = await client.list_tools()
        # Handle both ListToolsResult (standard MCP) and direct list (FastMCP internal)
        mcp_tools = getattr(result, "tools", result)

        for t in mcp_tools:
            # mcp.types.Tool has name, description, inputSchema
            adapter = MCPToolAdapter(
                name=t.name,
                description=t.description or f"{t.name} tool from MCP",
                parameters=t.inputSchema,
                client=client,
            )
            self.register(adapter)

    def unregister(self, name: str) -> None:
        self._tools.pop(name, None)
        self._local_embeddings.pop(name, None)

    def get(self, name: str) -> BaseTool | None:
        return self._tools.get(name)

    def all_tools(self) -> list[BaseTool]:
        return list(self._tools.values())

    # ------------------------------------------------------------------
    # Dynamic selection
    # ------------------------------------------------------------------

    async def select(
        self,
        user_message: str,
        max_tools: int = 6,
        category_filter: list[str] | None = None,
        name_filter: list[str] | None = None,
        exclude_names: list[str] | None = None,
        use_semantic_search: bool = False,
    ) -> list[BaseTool]:
        """
        Return up to *max_tools* tools that are relevant to *user_message*.

        Uses an embedding cosine-similarity function for production-grade
        semantic matching. Falls back to keyword scoring if embedding fails.

        Args:
            user_message: The raw user request.
            max_tools:    Maximum number of tools to surface per request.

        Returns:
            Sorted list of relevant :class:`BaseTool` instances.
        """
        if not self._tools:
            return []

        # If name_filter is provided (and not wildcard/empty), filter candidates.
        if name_filter and "*" not in name_filter:
            candidates = [self.get(name) for name in name_filter if self.get(name)]
        else:
            candidates = list(self._tools.values())

        # Filter by exclusions and categories
        selected = []
        for tool in candidates:
            if exclude_names and tool.name in exclude_names:
                continue
            if category_filter and tool.category.lower() not in [c.lower() for c in category_filter]:
                continue
            selected.append(tool)

        # If not using semantic search, return the filtered candidates directly
        if not use_semantic_search:
            logger.debug(
                "catalog.select.direct_filter",
                selected=[t.name for t in selected],
            )
            return selected

        # 1. Fetch user message embedding
        msg_embedding = None
        try:
            msg_embedding = await self._embed_provider.embed_query(user_message)
        except Exception as e:
            logger.error("catalog.select.embedding_failed", error=str(e))

        # 2. Score mapping
        scored: list[tuple[float, BaseTool]] = []
        for tool in selected:
            score = 0.0
            if msg_embedding is not None:
                # Lazy evaluation and caching of tool description embedding
                t_emb = await self._get_tool_embedding(tool)
                if t_emb:
                    score = self._cosine_similarity(msg_embedding, t_emb)
                else:
                    score = self._score(user_message, tool)
            else:
                score = self._score(user_message, tool)

            if score > 0.0:
                scored.append((score, tool))

        scored.sort(key=lambda x: x[0], reverse=True)
        selected_semantic = [t for _, t in scored[:max_tools]]

        logger.debug(
            "catalog.select.semantic",
            message_preview=user_message[:60],
            selected=[t.name for t in selected_semantic],
        )
        return selected_semantic

    async def _get_tool_embedding(self, tool: BaseTool) -> list[float]:
        """
        Retrieve (or compute and cache) the embedding for a tool's description.

        Cache hierarchy:
        1. In-process local dict (fastest, no network)
        2. Redis hash (shared across workers, survives restarts)
        3. Embedding provider API call (slowest, result written to both caches)
        """
        # 1. Local in-process cache hit
        if tool.name in self._local_embeddings:
            return self._local_embeddings[tool.name]

        # 2. Redis cache hit
        try:
            cached = await self._redis.hget(_EMBEDDING_CACHE_KEY, tool.name)
            if cached:
                emb: list[float] = json.loads(cached)
                self._local_embeddings[tool.name] = emb  # Warm local cache
                return emb
        except Exception as redis_err:
            logger.warning("catalog.redis_cache.read_failed", tool=tool.name, error=str(redis_err))

        # 3. Compute via embedding API
        try:
            emb = await self._embed_provider.embed_query(tool.description)
        except Exception as e:
            logger.error("catalog.tool_embedding_failed", tool=tool.name, error=str(e))
            return []

        # Write to both caches
        self._local_embeddings[tool.name] = emb
        try:
            await self._redis.hset(_EMBEDDING_CACHE_KEY, tool.name, json.dumps(emb))
            # Refresh TTL on every new write so frequently-used keys stay warm
            await self._redis.expire(_EMBEDDING_CACHE_KEY, _EMBEDDING_CACHE_TTL)
            logger.debug("catalog.redis_cache.written", tool=tool.name)
        except Exception as redis_err:
            logger.warning("catalog.redis_cache.write_failed", tool=tool.name, error=str(redis_err))

        return emb

    def _cosine_similarity(self, v1: list[float], v2: list[float]) -> float:
        """Compute cosine similarity between two vectors."""
        dot_product = sum(a * b for a, b in zip(v1, v2))
        magnitude1 = math.sqrt(sum(a * a for a in v1))
        magnitude2 = math.sqrt(sum(b * b for b in v2))
        if magnitude1 == 0 or magnitude2 == 0:
            return 0.0
        return dot_product / (magnitude1 * magnitude2)

    # ------------------------------------------------------------------
    # Scoring strategy — swap this method for semantic embeddings.
    # ------------------------------------------------------------------

    def _score(self, message: str, tool: BaseTool) -> float:
        """
        Heuristic keyword overlap score between *message* and a tool.

        Returns a float in [0, ∞).  Higher = more relevant.
        """
        message_tokens = set(re.findall(r"\w+", message.lower()))
        desc_tokens = set(re.findall(r"\w+", tool.description.lower()))
        overlap = message_tokens & desc_tokens
        # Normalise by description length to avoid bias toward long descriptions.
        return len(overlap) / max(len(desc_tokens), 1)
