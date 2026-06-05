"""
Agent Factory - provides pre-configured Orchestrator instances.
"""
from __future__ import annotations

from typing import Any

from agentix.agents.loader import AgentLoader
from agentix.core.llm import LLMClient
from agentix.core.orchestrator import Orchestrator
from agentix.registry.catalog import ToolCatalog


class AgentFactory:
    """Entry point for creating specialized agents."""

    @staticmethod
    def create(
        agent_name: str,
        catalog: ToolCatalog | None = None,
        memory: Any | None = None,
    ) -> Orchestrator:
        """
        Create an Orchestrator instance configured as the named agent.
        
        Args:
            agent_name: Name of the agent config (e.g. 'researcher').
            catalog: Optional shared tool catalog.
            memory: Optional shared session memory.
        """
        config = AgentLoader.load_by_name(agent_name)
        
        # Configure LLM if overrides exist in YAML
        llm = LLMClient(
            model=config.llm.model,
            temperature=config.llm.temperature,
            max_tokens=config.llm.max_tokens,
        )
        
        return Orchestrator(
            llm=llm,
            catalog=catalog,
            memory=memory,
            config=config,
        )

    @staticmethod
    def create_custom(
        yaml_path: str,
        catalog: ToolCatalog | None = None,
    ) -> Orchestrator:
        """Create an agent from an arbitrary YAML file path."""
        config = AgentLoader.load_from_yaml(yaml_path)
        
        llm = LLMClient(
            model=config.llm.model,
            temperature=config.llm.temperature,
            max_tokens=config.llm.max_tokens,
        )
        
        return Orchestrator(
            llm=llm,
            catalog=catalog,
            config=config,
        )

    @staticmethod
    async def create_auto(
        message: str,
        catalog: ToolCatalog | None = None,
        memory: Any | None = None,
    ) -> Orchestrator:
        """
        Automatically selects and creates an agent based on the user's message intent.
        Falls back to a generic Orchestrator if no strong match is found.
        """
        from agentix.agents.router import AgentRouter
        
        router = AgentRouter()
        best_agent = await router.route(message)
        
        if best_agent:
            return AgentFactory.create(
                agent_name=best_agent,
                catalog=catalog,
                memory=memory,
            )
        else:
            # Fallback to generic orchestrator
            return Orchestrator(
                catalog=catalog,
                memory=memory,
            )
