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

class SecurityTopicGuardrail(BaseGuardrail):
    """
    Guardrail that checks if the incoming user message is relevant to siber security / IT operations.
    Rejects general out-of-scope questions.
    """

    def __init__(self, llm: LLMClient | None = None) -> None:
        self._llm = llm or LLMClient(
            temperature=0.0,
            max_tokens=128,
            cache_enabled=True,
        )

    async def validate(self, session_id: str, message: str) -> GuardrailResult:
        log = logger.bind(session_id=session_id)
        
        messages = [
            {"role": "system", "content": _GUARDRAIL_SYSTEM_PROMPT},
            {"role": "user", "content": message},
        ]
        
        try:
            response = await self._llm.chat(messages)
            content = response.get("content", "").strip()
            
            if content.upper().startswith("PASS"):
                return GuardrailResult(passed=True)
            
            if content.upper().startswith("BLOCK"):
                # Extract the refusal message
                parts = content.split(":", 1)
                reason = "Out-of-scope query"
                refusal_message = parts[1].strip() if len(parts) > 1 else "I can only assist with cybersecurity and security operations."
                
                log.info("guardrail.blocked_query", query=message[:120], reason=reason)
                return GuardrailResult(passed=False, reason=reason, refusal_message=refusal_message)
            
            # Fallback pass if LLM output format is unexpected
            log.warning("guardrail.unexpected_output", content=content)
            return GuardrailResult(passed=True)
            
        except Exception as e:
            log.error("guardrail.validation_error", error=str(e))
            # Safe default: fail-open on network/llm errors to avoid blocking the system
            return GuardrailResult(passed=True)
