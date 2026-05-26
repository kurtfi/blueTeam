import os
import structlog
from typing import Optional

from soc_mcp.integrations.base import (
    ISiemProvider,
    ICaseManagementProvider,
    IEnrichmentProvider,
    ISoarProvider,
    IEndpointProvider,
    IFirewallProvider,
    IIamProvider
)

logger = structlog.get_logger(__name__)

class ProviderRegistry:
    def __init__(self):
        self._siem_provider: Optional[ISiemProvider] = None
        self._case_provider: Optional[ICaseManagementProvider] = None
        self._enrichment_provider: Optional[IEnrichmentProvider] = None
        self._soar_provider: Optional[ISoarProvider] = None
        self._endpoint_provider: Optional[IEndpointProvider] = None
        self._firewall_provider: Optional[IFirewallProvider] = None
        self._iam_provider: Optional[IIamProvider] = None

    def get_siem_provider(self) -> ISiemProvider:
        if not self._siem_provider:
            provider_name = os.getenv("SIEM_PROVIDER", "wazuh").lower()
            if provider_name == "wazuh":
                from soc_mcp.integrations.wazuh import WazuhProvider
                self._siem_provider = WazuhProvider()
            else:
                raise ValueError(f"Unknown SIEM_PROVIDER: {provider_name}")
        return self._siem_provider

    def get_case_management_provider(self) -> ICaseManagementProvider:
        if not self._case_provider:
            provider_name = os.getenv("CASE_MANAGEMENT_PROVIDER", "thehive").lower()
            if provider_name == "thehive":
                from soc_mcp.integrations.thehive import TheHiveProvider
                self._case_provider = TheHiveProvider()
            else:
                raise ValueError(f"Unknown CASE_MANAGEMENT_PROVIDER: {provider_name}")
        return self._case_provider

    def get_enrichment_provider(self) -> IEnrichmentProvider:
        if not self._enrichment_provider:
            provider_name = os.getenv("ENRICHMENT_PROVIDER", "cortex").lower()
            if provider_name == "cortex":
                from soc_mcp.integrations.cortex import CortexProvider
                self._enrichment_provider = CortexProvider()
            else:
                raise ValueError(f"Unknown ENRICHMENT_PROVIDER: {provider_name}")
        return self._enrichment_provider

    def get_soar_provider(self) -> ISoarProvider:
        if not self._soar_provider:
            provider_name = os.getenv("SOAR_PROVIDER", "dummy").lower()
            if provider_name in ("dummy", "shuffle"):
                if provider_name == "shuffle":
                    logger.warning("provider.soar.shuffle_bypassed", message="Shuffle is disabled. Falling back to Dummy SOAR Provider.")
                from soc_mcp.integrations.dummy import DummySoarProvider
                self._soar_provider = DummySoarProvider()
            else:
                raise ValueError(f"Unknown SOAR_PROVIDER: {provider_name}")
        return self._soar_provider

    def get_endpoint_provider(self) -> IEndpointProvider:
        if not self._endpoint_provider:
            provider_name = os.getenv("ENDPOINT_PROVIDER", "wazuh").lower()
            if provider_name == "wazuh":
                from soc_mcp.integrations.wazuh import WazuhProvider
                self._endpoint_provider = WazuhProvider()
            else:
                raise ValueError(f"Unknown ENDPOINT_PROVIDER: {provider_name}")
        return self._endpoint_provider

    def get_firewall_provider(self) -> IFirewallProvider:
        if not self._firewall_provider:
            provider_name = os.getenv("FIREWALL_PROVIDER", "dummy").lower()
            if provider_name == "dummy":
                from soc_mcp.integrations.dummy import DummyFirewallProvider
                self._firewall_provider = DummyFirewallProvider()
            else:
                raise ValueError(f"Unknown FIREWALL_PROVIDER: {provider_name}")
        return self._firewall_provider

    def get_iam_provider(self) -> IIamProvider:
        if not self._iam_provider:
            provider_name = os.getenv("IAM_PROVIDER", "dummy").lower()
            if provider_name == "dummy":
                from soc_mcp.integrations.dummy import DummyIamProvider
                self._iam_provider = DummyIamProvider()
            else:
                raise ValueError(f"Unknown IAM_PROVIDER: {provider_name}")
        return self._iam_provider

# Global registry instance
registry = ProviderRegistry()
