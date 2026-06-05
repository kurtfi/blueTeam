import os

import structlog
from triage_core.integrations.base import (
    ICaseManagementProvider,
    IEndpointProvider,
    IEnrichmentProvider,
    IFirewallProvider,
    IIamProvider,
    ISiemProvider,
    ISoarProvider,
)

logger = structlog.get_logger(__name__)


class ProviderRegistry:
    def __init__(self) -> None:
        self._siem_provider: ISiemProvider | None = None
        self._case_provider: ICaseManagementProvider | None = None
        self._enrichment_provider: IEnrichmentProvider | None = None
        self._soar_provider: ISoarProvider | None = None
        self._endpoint_provider: IEndpointProvider | None = None
        self._firewall_provider: IFirewallProvider | None = None
        self._iam_provider: IIamProvider | None = None

    def get_siem_provider(self) -> ISiemProvider:
        if not self._siem_provider:
            provider_name = os.getenv("SIEM_PROVIDER", "wazuh").lower()
            if provider_name == "wazuh":
                from triage_core.integrations.wazuh import WazuhProvider
                self._siem_provider = WazuhProvider()
            elif provider_name == "dummy":
                from triage_core.integrations.dummy import DummySiemProvider
                logger.info("provider.siem.dummy", message="Using DummySiemProvider (SIEM_PROVIDER=dummy)")
                self._siem_provider = DummySiemProvider()
            else:
                raise ValueError(f"Unknown SIEM_PROVIDER: {provider_name}")
        return self._siem_provider

    def get_case_management_provider(self) -> ICaseManagementProvider:
        if not self._case_provider:
            provider_name = os.getenv("CASE_MANAGEMENT_PROVIDER", "thehive").lower()
            if provider_name == "thehive":
                from triage_core.integrations.thehive import TheHiveProvider
                self._case_provider = TheHiveProvider()
            elif provider_name == "dummy":
                from triage_core.integrations.dummy import DummyCaseManagementProvider
                logger.info("provider.case.dummy", message="Using DummyCaseManagementProvider (CASE_MANAGEMENT_PROVIDER=dummy)")
                self._case_provider = DummyCaseManagementProvider()
            else:
                raise ValueError(f"Unknown CASE_MANAGEMENT_PROVIDER: {provider_name}")
        return self._case_provider

    def get_enrichment_provider(self) -> IEnrichmentProvider:
        if not self._enrichment_provider:
            provider_name = os.getenv("ENRICHMENT_PROVIDER", "cortex").lower()
            if provider_name == "cortex":
                from triage_core.integrations.cortex import CortexProvider
                self._enrichment_provider = CortexProvider()
            elif provider_name == "dummy":
                from triage_core.integrations.dummy import DummyEnrichmentProvider
                logger.info("provider.enrichment.dummy", message="Using DummyEnrichmentProvider (ENRICHMENT_PROVIDER=dummy)")
                self._enrichment_provider = DummyEnrichmentProvider()
            else:
                raise ValueError(f"Unknown ENRICHMENT_PROVIDER: {provider_name}")
        return self._enrichment_provider

    def get_soar_provider(self) -> ISoarProvider:
        if not self._soar_provider:
            provider_name = os.getenv("SOAR_PROVIDER", "dummy").lower()
            if provider_name in ("dummy", "shuffle"):
                if provider_name == "shuffle":
                    logger.warning(
                        "provider.soar.shuffle_bypassed",
                        message="Shuffle is disabled. Falling back to Dummy SOAR Provider.",
                    )
                from triage_core.integrations.dummy import DummySoarProvider
                self._soar_provider = DummySoarProvider()
            else:
                raise ValueError(f"Unknown SOAR_PROVIDER: {provider_name}")
        return self._soar_provider

    def get_endpoint_provider(self) -> IEndpointProvider:
        if not self._endpoint_provider:
            provider_name = os.getenv("ENDPOINT_PROVIDER", "wazuh").lower()
            if provider_name == "wazuh":
                from triage_core.integrations.wazuh import WazuhProvider
                self._endpoint_provider = WazuhProvider()
            elif provider_name == "dummy":
                from triage_core.integrations.dummy import DummyEndpointProvider
                logger.info("provider.endpoint.dummy", message="Using DummyEndpointProvider (ENDPOINT_PROVIDER=dummy)")
                self._endpoint_provider = DummyEndpointProvider()
            else:
                raise ValueError(f"Unknown ENDPOINT_PROVIDER: {provider_name}")
        return self._endpoint_provider

    def get_firewall_provider(self) -> IFirewallProvider:
        if not self._firewall_provider:
            provider_name = os.getenv("FIREWALL_PROVIDER", "dummy").lower()
            if provider_name == "dummy":
                from triage_core.integrations.dummy import DummyFirewallProvider
                self._firewall_provider = DummyFirewallProvider()
            else:
                raise ValueError(f"Unknown FIREWALL_PROVIDER: {provider_name}")
        return self._firewall_provider

    def get_iam_provider(self) -> IIamProvider:
        if not self._iam_provider:
            provider_name = os.getenv("IAM_PROVIDER", "dummy").lower()
            if provider_name == "dummy":
                from triage_core.integrations.dummy import DummyIamProvider
                self._iam_provider = DummyIamProvider()
            else:
                raise ValueError(f"Unknown IAM_PROVIDER: {provider_name}")
        return self._iam_provider


# Global registry instance
registry = ProviderRegistry()
