from abc import ABC, abstractmethod
from typing import Any


class ISiemProvider(ABC):
    @abstractmethod
    async def query_logs(self, query: str, time_range: str = "last 1 hour") -> str:
        """Query the SIEM for logs based on the given query and time range."""
        pass


class ICaseManagementProvider(ABC):
    @abstractmethod
    async def create_case(
        self, title: str = "", description: str = "", severity: int = 2, tags: list[str] | None = None
    ) -> str:
        """Create a new case in the case management system."""
        pass

    @abstractmethod
    async def add_case_note(self, case_id: str, note: str, task_title: str = "Investigation Note") -> str:
        """Add a note/task to an existing case."""
        pass

    @abstractmethod
    async def update_case_status(
        self, case_id: str, status: str, resolution_type: str = "TruePositive", summary: str = ""
    ) -> str:
        """Update the status of an existing case."""
        pass

    @abstractmethod
    async def create_alert(
        self,
        title: str = "",
        description: str = "",
        source: str = "Agentix",
        source_ref: str = "",
        severity: int = 2,
        tags: list[str] | None = None,
        observables: list[dict[str, Any]] | None = None,
    ) -> str:
        """Create an alert in the case management system for triage."""
        pass


class IEnrichmentProvider(ABC):
    @abstractmethod
    async def get_ip_reputation(self, ip_address: str) -> str:
        """Get the reputation of an IP address."""
        pass

    @abstractmethod
    async def get_file_reputation(self, file_hash: str) -> str:
        """Get the reputation of a file hash."""
        pass

    @abstractmethod
    async def get_domain_url_reputation(self, url_or_domain: str) -> str:
        """Get the reputation of a domain or URL."""
        pass


class ISoarProvider(ABC):
    @abstractmethod
    async def trigger_workflow(
        self, workflow_id: str, data: dict[str, Any] | None = None, webhook_url: str = ""
    ) -> str:
        """Trigger a SOAR workflow."""
        pass


class IEndpointProvider(ABC):
    @abstractmethod
    async def get_endpoint_info(self, agent_id: str) -> str:
        """Get detailed information about an endpoint/agent."""
        pass

    @abstractmethod
    async def isolate_endpoint(self, agent_id: str) -> str:
        """Isolate an endpoint from the network."""
        pass


class IFirewallProvider(ABC):
    @abstractmethod
    async def block_ip(self, ip_address: str) -> str:
        """Block an IP address at the firewall."""
        pass


class IIamProvider(ABC):
    @abstractmethod
    async def get_user_info(self, username: str) -> str:
        """Get information about a user account."""
        pass

    @abstractmethod
    async def disable_user_account(self, username: str) -> str:
        """Disable a user account."""
        pass
