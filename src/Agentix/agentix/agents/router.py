"""
LLM-Based Intent Agent Router.

Routes user requests to the most appropriate specialized agent by asking
a fast LLM to classify the intent.  This approach is **language-agnostic**
— it works equally well for Turkish, English, or any other language because
the LLM understands semantic meaning, not just keyword/embedding overlap.

Design decisions:
  - Uses a dedicated lightweight model (configurable via settings) so the
    routing call is cheap and fast (~200-400ms).
  - Temperature is fixed at 0 for deterministic classification.
  - The LLM returns structured JSON: {"agent": "<name>", "confidence": 0-1}.
  - Falls back to None (generic orchestrator) if confidence < threshold or
    if the LLM call fails for any reason.
"""

from __future__ import annotations

import json
from typing import Any

import structlog

from agentix.agents.loader import AgentLoader
from agentix.core.llm import LLMClient

logger = structlog.get_logger(__name__)

# System prompt for the routing LLM — kept minimal to reduce latency.
_ROUTER_SYSTEM_PROMPT = """\
You are an intent classifier for an AI platform.  Your ONLY job is to pick
the single best agent for the user's request, or reply "none" if no agent
fits well.

Available agents (name → role):
{agent_list}

Rules:
- Respond with ONLY a JSON object: {{"agent": "<agent_name>", "confidence": <0.0-1.0>}}
- "agent" must be one of the listed agent names, or "none".
- "confidence" is how sure you are (0 = no match, 1 = perfect match).
- Do NOT add any explanation, markdown, or extra text — just the JSON.
- Consider the semantic meaning of the request, regardless of its language.
""".strip()


class AgentRouter:
    """
    Selects the best matching agent for a given user message by asking
    a lightweight LLM to classify the user's intent against the available
    agent descriptions.

    This replaces the previous embedding cosine-similarity approach which
    struggled with cross-language queries (e.g. Turkish message vs English
    agent roles).
    """

    def __init__(self, model: str | None = None) -> None:
        """
        Args:
            model: Optional model override for the routing LLM.
                   If None, uses the platform's default LLM.
                   For cost efficiency, use a small/fast model like
                   ``gemma4:e4b``, ``qwen3.5:9b`` or ``gpt-4o-mini``.
        """
        # Low temperature + small max_tokens = fast, deterministic routing.
        self._llm = LLMClient(
            model=model,
            temperature=0.0,
            max_tokens=128,
            cache_enabled=True,  # Same message → same route (idempotent)
        )
        # Cache the agent list string so we don't rebuild it every call.
        self._agent_list_cache: str | None = None

    def _build_agent_list(self) -> str:
        """Build a compact 'name → role' list of all available agents."""
        if self._agent_list_cache is not None:
            return self._agent_list_cache

        agent_names = AgentLoader.list_available_agents()
        lines: list[str] = []
        for name in agent_names:
            try:
                config = AgentLoader.load_by_name(name)
                lines.append(f"- {name}: {config.role}")
            except (OSError, FileNotFoundError, ValueError) as e:
                logger.warning("router.load_agent_failed", agent=name, error=str(e))
                continue

        self._agent_list_cache = "\n".join(lines) if lines else "(no agents available)"
        return self._agent_list_cache

    async def route(
        self,
        user_message: str,
        threshold: float = 0.5,
    ) -> str | None:
        """
        Classify the user's intent and return the best agent name.

        Args:
            user_message: The raw user prompt (any language).
            threshold: Minimum confidence required to select an agent.
                       Requests below this confidence fall back to the
                       generic orchestrator.

        Returns:
            The name (e.g. ``'researcher'``) of the best matching agent,
            or ``None`` if no agent meets the confidence threshold.
        """
        agent_list = self._build_agent_list()

        # Fast-fail if no agents are configured.
        available_agents = AgentLoader.list_available_agents()
        if not available_agents:
            logger.info("router.no_agents_configured")
            return None

        system_prompt = _ROUTER_SYSTEM_PROMPT.format(agent_list=agent_list)

        messages: list[Any] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ]

        try:
            response = await self._llm.chat(messages)
        except Exception as e:
            logger.error("router.llm_call_failed", error=str(e))
            return None

        # Parse the LLM's JSON response.
        raw_content: str = response.get("content", "").strip()
        logger.debug("router.raw_response", content=raw_content[:200])

        parsed = self._extract_json(raw_content)
        if parsed is None:
            logger.warning("router.json_parse_failed", raw=raw_content[:200])
            return None

        agent_name = parsed.get("agent", "none").lower().strip()
        confidence = float(parsed.get("confidence", 0.0))

        logger.info(
            "router.classification_result",
            agent=agent_name,
            confidence=confidence,
            threshold=threshold,
        )

        # Validate the agent actually exists.
        if agent_name == "none" or agent_name not in available_agents:
            return None

        if confidence < threshold:
            logger.info("router.below_threshold", agent=agent_name, confidence=confidence)
            return None

        return agent_name

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_json(text: str) -> dict | None:
        r"""
        Robustly extract a JSON object from LLM output.

        Handles:
          - Raw JSON: ``{"agent": "researcher", "confidence": 0.9}``
          - Markdown fences: ``\`\`\`json\n{...}\n\`\`\` ``
          - JSON embedded in prose
        """
        import re

        if not text:
            return None

        # 1. Try direct parse
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # 2. Strip markdown code fences (```json ... ``` or ``` ... ```)
        fence_match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
        if fence_match:
            try:
                return json.loads(fence_match.group(1).strip())
            except json.JSONDecodeError:
                pass

        # 3. Find any JSON object in the text
        obj_match = re.search(r"\{[^}]+\}", text)
        if obj_match:
            try:
                return json.loads(obj_match.group())
            except json.JSONDecodeError:
                pass

        return None
