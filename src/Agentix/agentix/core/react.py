"""
ReAct (Reason + Act) loop implementation.

Cycle:
  Think  →  Act (tool call)  →  Observe (tool result)  →  repeat
           until final answer or max_iterations reached.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class StepType(StrEnum):
    THINK = "think"
    ACT = "act"
    OBSERVE = "observe"
    ANSWER = "answer"
    CONFIRM = "confirm"


@dataclass
class ReActStep:
    step_type: StepType
    content: str
    tool_name: str | None = None
    tool_input: dict[str, Any] | None = None
    tool_output: Any | None = None


@dataclass
class ReActTrace:
    """Full execution trace for a single user request."""

    request: str
    steps: list[ReActStep] = field(default_factory=list)
    final_answer: str | None = None
    iterations: int = 0

    def add_step(self, step: ReActStep) -> None:
        self.steps.append(step)
        self.iterations += 1

    def is_complete(self) -> bool:
        return self.final_answer is not None

    def to_dict(self) -> dict:
        return {
            "request": self.request,
            "final_answer": self.final_answer,
            "iterations": self.iterations,
            "steps": [
                {
                    "type": s.step_type.value,
                    "content": s.content,
                    "tool_name": s.tool_name,
                    "tool_input": s.tool_input,
                    "tool_output": str(s.tool_output) if s.tool_output is not None else None,
                }
                for s in self.steps
            ],
        }
