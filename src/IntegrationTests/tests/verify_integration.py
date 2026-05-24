import asyncio
from agentix.tools.main_server import _loaded, _skipped
from agentix.tools import mcp

async def main():
    print("--- Tool Loading Status ---")
    print(f"Loaded tools: {len(_loaded)}")
    for tool in _loaded:
        print(f" [+] {tool}")

    print(f"\nSkipped tools: {len(_skipped)}")
    for tool in _skipped:
        print(f" [-] {tool}")

    print("\n--- Registered Tools in MCP ---")
    # list_tools can be async or sync depending on FastMCP version, usually sync in FastMCP
    # but let's check if it's a coroutine
    tools_res = mcp.list_tools()
    if asyncio.iscoroutine(tools_res):
        tools = await tools_res
    else:
        tools = tools_res
        
    registered_tools = [t.name for t in tools]
    print(f"Total tools in MCP: {len(registered_tools)}")

    soc_tools = [
        "create_thehive_case", 
        "get_ip_reputation", 
        "get_file_reputation", 
        "get_domain_url_reputation", 
        "get_ad_user_info", 
        "query_siem_logs", 
        "isolate_endpoint", 
        "block_ip", 
        "disable_user_account"
    ]

    print("\nChecking SOC tools:")
    for st in soc_tools:
        status = "OK" if st in registered_tools else "MISSING"
        print(f" {status}: {st}")

if __name__ == "__main__":
    asyncio.run(main())
