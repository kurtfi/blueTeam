"""
YAML loader for Agent configurations.
"""
from __future__ import annotations

from pathlib import Path

from agentix.agents.schema import AgentConfig
from yaml import safe_load


class AgentLoader:
    """Utility to load and validate YAML Agent configurations."""

    @staticmethod
    def load_from_yaml(filepath: Path | str) -> AgentConfig:
        """Load a single agent from a YAML file."""
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Agent config not found: {path}")

        with open(path, encoding="utf-8") as f:
            data = safe_load(f)

        return AgentConfig(**data)

    @staticmethod
    def load_by_name(agent_name: str) -> AgentConfig:
        """Find an agent by name in the internal config directory."""
        # Use relative path to package storage
        config_dir = Path(__file__).parent / "configs"
        yaml_path = config_dir / f"{agent_name}.yaml"
        return AgentLoader.load_from_yaml(yaml_path)

    @staticmethod
    def list_available_agents() -> list[str]:
        """List all agent names available in the configs directory."""
        config_dir = Path(__file__).parent / "configs"
        if not config_dir.exists():
            return []
        
        return [f.stem for f in config_dir.glob("*.yaml")]
