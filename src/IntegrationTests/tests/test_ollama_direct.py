import asyncio
import json
import logging
import sys
from agentix.core.providers.ollama_provider import OllamaProvider

logging.basicConfig(level=logging.INFO, stream=sys.stdout)
logger = logging.getLogger("test_ollama_direct")

async def main():
    provider = OllamaProvider(model="gemma4:e4b")
    
    # Simple tool definition
    tools = [
        {
            "type": "function",
            "function": {
                "name": "find_playbook_for_alert",
                "description": "Find appropriate playbooks for a given MITRE technique ID.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "mitre_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "MITRE ATT&CK technique IDs (e.g. ['T1003.008'])"
                        }
                    },
                    "required": ["mitre_ids"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "trigger_playbook",
                "description": "Trigger a security playbook.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "playbook_id": {"type": "string"},
                        "agent_id": {"type": "string"}
                    },
                    "required": ["playbook_id"]
                }
            }
        }
    ]

    system_prompt = "You are a SOC Analyst. Use playbooks to respond to alerts. Always start by finding the playbook using find_playbook_for_alert."
    user_prompt = "T1003.008 alert came in for agent 000. What is the playbook and what should we do?"

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt}
    ]

    print("--- Turn 1 Request ---")
    print(f"Messages: {json.dumps(messages, indent=2)}")
    response1 = await provider.chat(messages, tools=tools)
    print("\n--- Turn 1 Response ---")
    print(json.dumps(response1, indent=2))

    if response1.get("tool_calls"):
        # Append assistant response
        # In OpenAI structure, tool_calls goes to the assistant message
        tc = response1["tool_calls"][0]
        messages.append({
            "role": "assistant",
            "content": response1["content"],
            "tool_calls": response1["tool_calls"]
        })
        
        # Simulate tool observation
        observation = "Playbook PB-001 found for T1003.008. Steps: 1. query_siem_logs, 2. isolate_endpoint."
        messages.append({
            "role": "tool",
            "tool_call_id": tc["id"],
            "content": observation
        })

        print("\n--- Turn 2 Request ---")
        print(f"Messages: {json.dumps(messages, indent=2)}")
        response2 = await provider.chat(messages, tools=tools)
        print("\n--- Turn 2 Response ---")
        print(json.dumps(response2, indent=2))
    else:
        print("\nNo tool call in Turn 1.")

if __name__ == "__main__":
    asyncio.run(main())
