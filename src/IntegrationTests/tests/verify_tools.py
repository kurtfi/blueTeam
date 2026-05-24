import asyncio
from pathlib import Path
from agentix.tools.system.file_manager import FileManager
from agentix.tools.system.terminal import Terminal

async def verify():
    print("--- Verifying FileManager Security ---")
    fm = FileManager()
    # 1. Path Traversal
    result = await fm.execute(operation="read", path="../../../etc/passwd")
    print(f"Path Traversal Blocked: {not result.success}")
    if not result.success:
        print(f"  Error: {result.error}")
        
    # 2. HITL Confirmation
    conf_needed = fm.requires_confirmation(operation="delete", path="test.txt")
    print(f"Delete requires confirmation: {conf_needed}")

    print("\n--- Verifying Terminal Security ---")
    term = Terminal()
    # 1. Metacharacter block
    result = await term.execute(command="ls; rm -rf /")
    print(f"Metacharacter ';' Blocked: {not result.success}")
    if not result.success:
        print(f"  Error: {result.error}")

    # 2. HITL Confirmation
    conf_needed = term.requires_confirmation(mode="unrestricted", command="any")
    print(f"Unrestricted mode requires confirmation: {conf_needed}")

    print("\n--- DONE ---")

if __name__ == "__main__":
    asyncio.run(verify())
