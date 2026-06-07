from agentix.core.guardrails.manager import GuardrailManager
from agentix.core.guardrails.security_topic import SecurityTopicGuardrail
from agentix.core.llm import LLMClient


class GuardrailFactory:
    """
    Factory class to construct GuardrailManager instances.
    Enforces Dependency Inversion by isolating instantiation details.
    """

    @staticmethod
    def create_default(llm: LLMClient) -> GuardrailManager:
        """Builds a default GuardrailManager pre-configured with active guardrails."""
        manager = GuardrailManager()
        manager.register(SecurityTopicGuardrail(llm=llm))
        return manager
