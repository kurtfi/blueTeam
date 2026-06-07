from agentix.core.guardrails.base import BaseGuardrail, GuardrailResult

class GuardrailManager:
    """
    Manages and executes a pipeline of guardrails.
    Conforms to SOLID principles by allowing dynamic registration
    and encapsulating the execution logic.
    """

    def __init__(self, guardrails: list[BaseGuardrail] | None = None) -> None:
        self._guardrails = list(guardrails) if guardrails else []

    def register(self, guardrail: BaseGuardrail) -> None:
        """Dynamically add a guardrail to the pipeline."""
        self._guardrails.append(guardrail)

    async def verify(self, session_id: str, message: str, session_source: str = "USER") -> GuardrailResult:
        """
        Execute all registered guardrails sequentially.
        Aborts and returns the first block result.
        """
        for gr in self._guardrails:
            result = await gr.validate(session_id, message, session_source)
            if not result.passed:
                return result
        return GuardrailResult(passed=True)
