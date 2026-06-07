from abc import ABC, abstractmethod
from dataclasses import dataclass

@dataclass
class GuardrailResult:
    passed: bool
    reason: str | None = None
    refusal_message: str | None = None

class BaseGuardrail(ABC):
    @abstractmethod
    async def validate(self, session_id: str, message: str) -> GuardrailResult:
        """Run validation on the user message."""
        pass
