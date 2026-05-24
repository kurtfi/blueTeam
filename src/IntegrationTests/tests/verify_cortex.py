import asyncio
import os
import sys
from dotenv import load_dotenv

# Load environment variables
env_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../Agentix/.env"))
load_dotenv(dotenv_path=env_path)

# We need to add src/SOCMCP to sys.path so we can import from soc_mcp
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../src/SOCMCP")))
# Also load agentic-common settings
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../src/AgenticCommon")))

from soc_mcp.integrations.cortex import CortexProvider

async def main():
    print("=== Cortex / VirusTotal Integration Test ===")
    
    # 1. Print configuration info (redacting api key)
    cortex_url = os.getenv("CORTEX_URL", "http://localhost:9001")
    cortex_api_key = os.getenv("CORTEX_API_KEY", "")
    print(f"Cortex URL    : {cortex_url}")
    print(f"Cortex API Key: {'configured (' + cortex_api_key[:6] + '...)' if cortex_api_key else 'NOT SET'}")
    
    if not cortex_api_key:
        print("✗ Error: CORTEX_API_KEY is not configured in environment variables.")
        return

    # 2. Instantiate CortexProvider
    provider = CortexProvider()
    
    # 3. Test IP reputation check (which uses VirusTotal_GetReport_3_1)
    test_ip = "8.8.8.8"
    print(f"\n[Test] Running VirusTotal analysis for IP: {test_ip}...")
    
    try:
        result = await provider.get_ip_reputation(test_ip)
        print("\n=== ANALYSIS RESULT ===")
        print(result)
        print("=======================")
        
        if "Cortex Analiz Başarılı" in result:
            print("\n✓ Success: Cortex and VirusTotal analyzer are fully functional!")
        elif "Error: Analyzer" in result:
            print("\n✗ Error: VirusTotal analyzer might not be enabled or found in Cortex.")
        else:
            print("\n⚠ Notice: Analysis completed but with unexpected result. Please check details above.")
            
    except Exception as e:
        print(f"\n✗ Error executing analysis: {e}")

if __name__ == "__main__":
    asyncio.run(main())
