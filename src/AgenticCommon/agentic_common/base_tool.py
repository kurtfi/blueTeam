"""
BaseTool — abstract base class for every Agentix tool.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class ToolResult:
    """Standard result envelope returned by every tool execution."""

    success: bool
    output: Any = None
    error: str | None = None


class BaseTool(ABC):
    """
    Abstract base for all Agentix tools.
    """

    #: Unique, snake_case identifier for this tool.
    name: str

    #: Human-readable description — used by the intent-matching engine
    #: to decide whether this tool is relevant for a given request.
    description: str

    #: Category tag.  Used for grouping and coarse-grained filtering.
    #: One of: "system", "data", "action", "ux"
    category: str = "system"

    #: JSON Schema for the tool's input parameters (OpenAI function-calling
    #: compatible format).
    parameters: dict[str, Any] = {}

    #: Whether this tool requires a sandbox / elevated permission check.
    requires_sandbox: bool = False

    # ------------------------------------------------------------------
    # Concrete helpers — do not override unless necessary.
    # ------------------------------------------------------------------

    def to_openai_schema(self) -> dict[str, Any]:
        """
        Return the OpenAI-compatible tool schema dict.
        """
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }

    def to_registry_entry(self) -> dict[str, Any]:
        """
        Return a serialisable dict for the Tool Registry / catalog.
        """
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "requires_sandbox": self.requires_sandbox,
            "parameters": self.parameters,
        }

    # ------------------------------------------------------------------
    # Abstract interface — implement in every subclass.
    # ------------------------------------------------------------------

    @abstractmethod
    async def execute(self, context: dict[str, Any] | None = None, **kwargs: Any) -> ToolResult:
        """
        Execute the tool's action.
        """
        ...

    def requires_confirmation(self, **kwargs: Any) -> bool:
        """
        Check if the tool call requires manual human approval.
        """
        return False
