# Adding a New SOC Integration

This guide details how to add a new third-party security platform integration (such as Splunk, Suricata, or MISP) to the decoupled `SOCMCP` server.

---

## 1. Architecture: The Integration Provider Pattern

To avoid coupling agent tools directly to specific vendor implementations, `SOCMCP` uses an abstract **Provider/Strategy Pattern**.
- **Base Client Contract**: Defined under `src/SOCMCP/soc_mcp/integrations/base.py`.
- **Registry**: Resolves which client class to instantiate at runtime based on the `*_PROVIDER` environment variables (e.g. `SIEM_PROVIDER=wazuh` vs `SIEM_PROVIDER=splunk`).

```
              ┌────────────────────────────────┐
              │   BaseIntegrationProvider      │
              └───────────────┬────────────────┘
                              │ (inherits)
              ┌───────────────▼────────────────┐
              │    SplunkIntegrationProvider   │
              └────────────────────────────────┘
```

---

## 2. Implementing a New Provider

Let's walk through implementing a new firewall provider integration called `pfSense`.

### Step 1: Subclass the Base Provider
Create a new file under `src/SOCMCP/soc_mcp/integrations/pfsense.py`:

```python
from typing import Dict, Any
import httpx
from soc_mcp.integrations.base import BaseFirewallProvider

class PFSenseProvider(BaseFirewallProvider):
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.url = config.get("PFSENSE_API_URL")
        self.api_key = config.get("PFSENSE_API_KEY")
        self.verify_ssl = config.get("PFSENSE_VERIFY_SSL", True)

    async def block_ip(self, ip_address: str, duration_seconds: int) -> bool:
        """
        Sends an HTTP POST to pfSense API to add a block rule to the firewall table.
        """
        headers = {"X-API-Key": self.api_key}
        payload = {"ip": ip_address, "action": "block", "duration": duration_seconds}
        
        async with httpx.AsyncClient(verify=self.verify_ssl) as client:
            response = await client.post(f"{self.url}/api/v1/firewall/rules", json=payload, headers=headers)
            return response.status_code == 201

    async def get_rules(self) -> Dict[str, Any]:
        """
        Retrieves active rules from the firewall console.
        """
        headers = {"X-API-Key": self.api_key}
        async with httpx.AsyncClient(verify=self.verify_ssl) as client:
            response = await client.get(f"{self.url}/api/v1/firewall/rules", headers=headers)
            return response.json()
```

### Step 2: Register in the Integration Registry
Open `src/SOCMCP/soc_mcp/integrations/registry.py` and register your new provider class:

```python
from soc_mcp.integrations.registry import provider_registry
from soc_mcp.integrations.pfsense import PFSenseProvider

# Register pfsense as a valid option for the FIREWALL provider category
provider_registry.register("firewall", "pfsense", PFSenseProvider)
```

### Step 3: Configure Environment
Activate the integration in your `.env` config file by changing the provider string and supplying variables:

```ini
# Change provider from 'dummy' to 'pfsense'
FIREWALL_PROVIDER=pfsense

# Supply specific configuration keys (will be parsed into the client config dict)
PFSENSE_API_URL=https://192.168.1.1:8443
PFSENSE_API_KEY=pfsense-token-here
PFSENSE_VERIFY_SSL=false
```

---

## 3. Testing the Integration

Write an integration connectivity test inside `src/IntegrationTests/tests/` to verify communication with your provider:

```python
import pytest
from soc_mcp.integrations.registry import provider_registry

@pytest.mark.asyncio
async def test_pfsense_connectivity():
    # Load registry class manually for verification
    provider_class = provider_registry.get("firewall", "pfsense")
    assert provider_class is not None
    
    # Initialize with mock configuration parameters
    client = provider_class({
        "PFSENSE_API_URL": "http://localhost:18080",
        "PFSENSE_API_KEY": "test-key"
    })
    
    # Assert methods are callable
    assert hasattr(client, "block_ip")
    assert hasattr(client, "get_rules")
```
