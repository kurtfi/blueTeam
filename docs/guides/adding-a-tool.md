# Adding a New Tool

This guide explains how to add a new security capability (tool) to the platform. Tools can either be added directly as internal Python tools within `Agentix` or exposed via the decoupled `SOCMCP` server.

---

## 1. Creating a Local Python Tool

Internal tools run within the core orchestrator. We define tools using standard Python functions decorated with descriptions and Pydantic validation schemas.

### Step 1: Define the Tool Function
Create a new file or add a function in `src/Agentix/agentix/tools/custom_tool.py`:

```python
from pydantic import BaseModel, Field
from agentic_common.sandbox import SessionWorkspace

class IPBlockInput(BaseModel):
    ip_address: str = Field(..., description="The IPv4 address to block on the gateway firewall")
    duration_minutes: int = Field(default=60, description="Duration of the block rule in minutes")

def block_gateway_ip(workspace: SessionWorkspace, args: IPBlockInput) -> str:
    """
    Blocks a suspicious IP address on the gateway firewall interface.
    This action requires human-in-the-loop confirmation before running.
    """
    # Verify path sandbox security (if writing local config files)
    log_path = workspace.resolve_safe_path("firewall_changes.log")
    
    # Execution logic here (e.g. hitting real API or writing config file)
    with open(log_path, "a") as f:
        f.write(f"Blocked IP: {args.ip_address} for {args.duration_minutes} minutes\n")
        
    return f"Successfully added firewall rule to block {args.ip_address} for {args.duration_minutes} minutes."
```

### Step 2: Register the Tool in Agentix
Register your tool in `src/Agentix/agentix/registry/tools.py`:

```python
from agentix.registry import tool_registry
from agentix.tools.custom_tool import block_gateway_ip, IPBlockInput

# Register the tool, flagging it as requiring human-in-the-loop validation
tool_registry.register(
    name="block_gateway_ip",
    func=block_gateway_ip,
    input_schema=IPBlockInput,
    requires_confirmation=True  # Gated by HITL!
)
```

---

## 2. Exposing an MCP Tool via FastMCP

If your tool interacts with external services (like সুরিকাটা/Suricata or MISP) and requires isolated credentials, add it to the `SOCMCP` server instead.

### Step 1: Write FastMCP Tool
Add your function to `src/SOCMCP/soc_mcp/server.py`:

```python
from fastmcp import FastMCP
import httpx

mcp = FastMCP("SOC Integration Server")

@mcp.tool()
async def query_misp_threat_intel(indicator: str) -> str:
    """
    Queries the local MISP instance to check if an indicator of compromise (IOC) matches known campaigns.
    """
    # Fetch credentials from isolated environment variables
    misp_url = os.environ.get("MISP_URL", "http://localhost:8088")
    misp_key = os.environ.get("MISP_API_KEY")
    
    headers = {"Authorization": misp_key, "Accept": "application/json"}
    
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{misp_url}/attributes/search/value:{indicator}", headers=headers)
        if response.status_code != 200:
            return f"MISP query failed with status code {response.status_code}"
            
        data = response.json()
        if not data.get("response", {}).get("Attribute"):
            return f"Indicator '{indicator}' not found in MISP database."
            
        return f"Found MISP Threat Intel: {data}"
```

---

## 3. Writing Unit Tests for Your Tool

Create a unit test inside `src/Agentix/tests/` to verify your tool's logic under pytest.

```python
import pytest
from agentic_common.sandbox import SessionWorkspace
from agentix.tools.custom_tool import block_gateway_ip, IPBlockInput

def test_block_gateway_ip(tmp_path):
    # Initialize workspace using test directory
    workspace = SessionWorkspace(session_id="test_sess", root_dir=tmp_path)
    
    args = IPBlockInput(ip_address="198.51.100.15", duration_minutes=30)
    result = block_gateway_ip(workspace, args)
    
    assert "Successfully added firewall rule" in result
    assert "198.51.100.15" in result
    
    # Assert file was correctly written inside the sandbox
    log_file = tmp_path / "firewall_changes.log"
    assert log_file.exists()
    assert "198.51.100.15" in log_file.read_text()
```
Run the test suite using `uv`:
```bash
uv run pytest src/Agentix/tests
```
