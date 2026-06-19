"""
Pydantic schemas for YAML-based Agent definitions.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class ToolFilter(BaseModel):
    """Filter criteria for limiting tools in the catalog."""

    categories: list[str] = Field(default_factory=list)
    names: list[str] = Field(default_factory=list)
    exclude_names: list[str] = Field(default_factory=list)


class LLMConfig(BaseModel):
    """Optional LLM parameter overrides."""

    model: str | None = None
    temperature: float = 0.0
    max_tokens: int = 4096


class AgentConfig(BaseModel):
    """Full configuration for a specialized Agent."""

    id: str | None = None
    name: str
    role: str
    system_prompt_override: str | None = None
    tool_filters: ToolFilter = Field(default_factory=ToolFilter)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    rag_enabled: bool = True
    max_iterations: int = 10
