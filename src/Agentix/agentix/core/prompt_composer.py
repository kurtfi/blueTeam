"""
System Prompt Composer — compiling final system prompts with dynamic context elements.
"""

from __future__ import annotations

from agentic_common.base_tool import BaseTool

_SYSTEM_PROMPT = """\
You are Agentix, a Tool-First AI orchestrator.

When responding, follow this logical flow:
1. Thought: Briefly explain your reasoning and which tool you will use.
2. Tool Call: Call the appropriate function from the available tools.
3. Final Answer: Once you have all necessary information, provide a comprehensive response prefixed with 'Final Answer:'.

Rules:
- Only use the tools provided to you.
- If a task is unsafe or out of scope, refuse and explain why.
- For academic research, always prioritize arXiv findings and download relevant PDFs for analysis.
"""


class SystemPromptComposer:
    """
    Responsible for compiling the final system prompt by combining
    the base configuration prompt with dynamic tools, playbooks,
    and retrieved RAG context passages.
    """

    def __init__(self, base_prompt: str | None = None) -> None:
        self.base_prompt = base_prompt or _SYSTEM_PROMPT

    def compose(
        self,
        available_tools: list[BaseTool] | None = None,
        playbooks_str: str | None = None,
        rag_context: str | None = None,
    ) -> str:
        prompt = self.base_prompt

        # Inject Dynamic Tools List
        if available_tools:
            tools_section = "\n\n### Available Tools (Dynamic)\n"
            for t in available_tools:
                desc = t.description or "No description provided."
                desc_clean = desc.replace("\n", " ").strip()
                tools_section += f"- **{t.name}**: {desc_clean}\n"
            prompt += tools_section

        # Inject Dynamic Playbooks Catalog (only if agent has playbook tools)
        has_playbook_tools = available_tools and any(
            t.name in ("trigger_playbook", "list_playbooks", "find_playbook_for_alert") for t in available_tools
        )
        if playbooks_str and has_playbook_tools:
            prompt += f"\n\n### Available Playbooks (Dynamic)\n{playbooks_str}\n"

        # Inject RAG context block if provided
        if rag_context:
            prompt += f"\n\n{rag_context}"

        return prompt
