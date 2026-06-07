from agentix.core.guardrails.base import BaseGuardrail, GuardrailResult

class GuardrailEngine:
    """
    Executes a chain of guardrails sequentially.
    Stops and returns the first block result if any guardrail fails.
    """

    def __init__(self, guardrails: list[BaseGuardrail]) -> None:
        self._guardrails = guardrails

    async def run(self, session_id: str, message: str) -> GuardrailResult:
        for gr in self._guardrails:
            result = await gr.validate(session_id, message)
            if not result.passed:
                return result
        return GuardrailResult(passed=True)
