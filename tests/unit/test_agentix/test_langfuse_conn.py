import sys
from pathlib import Path

# Add src/Agentix and src/AgenticCommon to sys.path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir))
sys.path.insert(0, str(root_dir.parent / "AgenticCommon"))

import asyncio

import pytest
from agentic_common.settings import settings
from agentix.core.observability import obs


@pytest.mark.asyncio
async def test_langfuse():
    print("Checking Langfuse Settings...")
    print(f"Enabled: {settings.langfuse_enabled}")
    print(f"Host: {settings.langfuse_host}")
    print(f"Public Key: {settings.langfuse_public_key[:8]}...")

    trace = obs.trace(name="test_trace", session_id="test_session")
    if trace:
        print("Trace created successfully.")
        generation = trace.generation(name="test_gen", model="test_model", input="hello")
        await asyncio.sleep(1)
        generation.end(output="world")
        obs.flush()
        print("Data flushed to Langfuse.")
    else:
        print("Failed to create trace. Is Langfuse enabled and keys set?")


if __name__ == "__main__":
    asyncio.run(test_langfuse())
