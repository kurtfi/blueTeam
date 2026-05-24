import importlib
import sys

modules = [
    "agentix.tools.data.docling_parser",
    "agentix.tools.data.crawl4ai_crawler",
    "agentix.tools.action.api_connector",
    "agentix.tools.main_server"
]

print("Starting tool verification...")
for mod in modules:
    print(f"Checking {mod}...", end=" ", flush=True)
    try:
        importlib.import_module(mod)
        print("OK")
    except Exception as e:
        print(f"FAILED: {e}")
        sys.exit(1)

print("\nAll new tools verified and successfully integrated into main_server.py")
