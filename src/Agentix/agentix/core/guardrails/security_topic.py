from agentix.core.guardrails.base import BaseGuardrail, GuardrailResult
from agentix.core.llm import LLMClient
import structlog

logger = structlog.get_logger(__name__)

_GUARDRAIL_SYSTEM_PROMPT = """\
You are a security guardrail classifier. Determine if the user's message is related to:
1. Cybersecurity (incidents, threat hunting, malware, firewalls, threat actors, CVEs, etc.)
2. Log analysis (analysing raw logs, SIEM logs, firewall logs, web server logs, etc.)
3. Threat intelligence (checking IP reputation, domain/URL reputation, file hashes, etc.)
4. IT / network security operations, security tools, or configurations.
5. Polite greetings or social small talk (e.g., "Merhaba", "Hi", "nasılsın", "teşekkürler").

If the message is related to any of these, respond with ONLY:
PASS

If it is NOT related to security operations, IT infrastructure, or greetings (e.g., cooking recipes, general programming unrelated to security, sports, literature, finance, jokes, etc.), you must refuse it. Respond with:
BLOCK: <Polite refusal message in the same language as the user's query explaining that you can only help with security operations and log/threat analysis>
"""

from enum import Enum, auto

class GuardrailDecision(Enum):
    PASS = auto()
    BLOCK = auto()
    UNKNOWN = auto()


class ParsedResponse:
    def __init__(self, decision: GuardrailDecision, refusal_message: str | None = None) -> None:
        self.decision = decision
        self.refusal_message = refusal_message


class GuardrailResponseParser:
    """
    Parses LLM chat responses to extract guardrail decisions.
    Conforms to SRP by separating raw LLM text parsing from the guardrail validation logic.
    """
    
    DEFAULT_REFUSAL = "I can only assist with cybersecurity and security operations."
    
    @classmethod
    def parse(cls, content: str) -> ParsedResponse:
        """
        Parses LLM response content and returns a ParsedResponse.
        Expects either:
          - PASS
          - BLOCK: <refusal message>
        """
        normalized = content.strip()
        upper_content = normalized.upper()
        
        if upper_content.startswith("PASS"):
            return ParsedResponse(decision=GuardrailDecision.PASS)
            
        if upper_content.startswith("BLOCK"):
            parts = normalized.split(":", 1)
            refusal_message = parts[1].strip() if len(parts) > 1 else cls.DEFAULT_REFUSAL
            return ParsedResponse(
                decision=GuardrailDecision.BLOCK,
                refusal_message=refusal_message
            )
            
        return ParsedResponse(decision=GuardrailDecision.UNKNOWN)


class SecurityTopicGuardrail(BaseGuardrail):
    """
    Guardrail that checks if the incoming user message is relevant to cybersecurity / IT operations.
    Rejects general out-of-scope questions.
    Only checks sessions where source == 'USER'.
    """

    def __init__(self, llm: LLMClient) -> None:
        self._llm = llm

    def should_run(self, session_source: str) -> bool:
        """Only apply guardrails to USER chat sessions. Bypassed for SIEM webhooks."""
        return session_source == "USER"

    def _build_messages(self, user_message: str) -> list[dict[str, str]]:
        """Separate prompt formatting from execution logic (SRP)."""
        return [
            {"role": "system", "content": _GUARDRAIL_SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ]

    async def _validate(self, session_id: str, message: str) -> GuardrailResult:
        log = logger.bind(session_id=session_id)
        messages = self._build_messages(message)
        
        try:
            response = await self._llm.chat(messages)
            content = response.get("content", "").strip()
            
            parsed = GuardrailResponseParser.parse(content)
            
            if parsed.decision == GuardrailDecision.PASS:
                return GuardrailResult(passed=True)
            
            if parsed.decision == GuardrailDecision.BLOCK:
                reason = "Out-of-scope query"
                log.info("guardrail.blocked_query", query=message[:120], reason=reason)
                return GuardrailResult(passed=False, reason=reason, refusal_message=parsed.refusal_message)
            
            # Fallback pass if LLM output format is unexpected
            log.warning("guardrail.unexpected_output", content=content)
            return GuardrailResult(passed=True)
            
        except Exception as e:
            log.error("guardrail.validation_error", error=str(e))
            # Safe default: fail-open on network/llm errors to avoid blocking the system
            return GuardrailResult(passed=True)
