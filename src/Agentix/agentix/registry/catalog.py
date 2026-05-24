"""
ToolCatalog — dynamic tool registry and intent-based selection.

Tools are registered at startup and selected per-request based on
semantic similarity between the user's message and each tool's description.
"""
from __future__ import annotations

import math
import re
from typing import TYPE_CHECKING

import structlog
from agentic_common.embeddings import EmbeddingFactory
from agentic_common.settings import settings
from agentic_common.base_tool import BaseTool

if TYPE_CHECKING:
    pass

logger = structlog.get_logger(__name__)


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
        self._tool_embeddings: dict[str, list[float]] = {}
        self._embed_provider = EmbeddingFactory.create_provider()

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
        self._tool_embeddings.pop(name, None)

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

        # If name_filter is explicitly provided, return all matching tools directly.
        # This prevents semantic filtering from discarding necessary playbook tools.
        if name_filter:
            selected = []
            for name in name_filter:
                tool = self.get(name)
                if tool:
                    if category_filter and tool.category.lower() not in [c.lower() for c in category_filter]:
                        continue
                    selected.append(tool)
            logger.debug(
                "catalog.select.bypass_by_name_filter",
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
        for tool in self._tools.values():
            # 2.1 Apply Filters
            if category_filter and tool.category.lower() not in [c.lower() for c in category_filter]:
                continue
            if name_filter and tool.name.lower() not in [n.lower() for n in name_filter]:
                continue

            score = 0.0
            if msg_embedding is not None:
                # Lazy evaluation and caching of tool description embedding
                if tool.name not in self._tool_embeddings:
                    try:
                        t_emb = await self._embed_provider.embed_query(tool.description)
                        self._tool_embeddings[tool.name] = t_emb
                    except Exception as e:
                        logger.error("catalog.tool_embedding_failed", tool=tool.name, error=str(e))
                        self._tool_embeddings[tool.name] = []

                t_emb = self._tool_embeddings.get(tool.name, [])
                if t_emb:
                    score = self._cosine_similarity(msg_embedding, t_emb)
                else:
                    score = self._score(user_message, tool)
            else:
                score = self._score(user_message, tool)

            if score > 0.0:
                scored.append((score, tool))

        scored.sort(key=lambda x: x[0], reverse=True)
        selected = [t for _, t in scored[:max_tools]]

        logger.debug(
            "catalog.select",
            message_preview=user_message[:60],
            selected=[t.name for t in selected],
        )
        return selected

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
