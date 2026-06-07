from abc import ABC, abstractmethod
from dataclasses import dataclass

@dataclass
class GuardrailResult:
    passed: bool
    reason: str | None = None
    refusal_message: str | None = None

class BaseGuardrail(ABC):
    def should_run(self, session_source: str) -> bool:
        """
        Determine if the guardrail should execute based on the session source.
        By default, guardrails run for all sources. Subclasses can override this.
        """
        return True

    async def validate(self, session_id: str, message: str, session_source: str = "USER") -> GuardrailResult:
        """
        Template method that handles execution policies (like source filtering)
        before executing the concrete validation logic.
        """
        if not self.should_run(session_source):
            return GuardrailResult(passed=True)
        return await self._validate(session_id, message)

    @abstractmethod
    async def _validate(self, session_id: str, message: str) -> GuardrailResult:
        """Core validation logic to be implemented by concrete guardrails."""
        pass
