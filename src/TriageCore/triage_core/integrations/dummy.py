import json
import os
import uuid
from typing import Any

import httpx
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


# ─────────────────────────────────────────────────────────────────────────────
# Dummy SIEM Provider
# ─────────────────────────────────────────────────────────────────────────────

_SIEM_BRUTE_FORCE = {
    "status": "success",
    "hits": [
        {
            "@timestamp": "2026-06-05T10:00:01.000Z",
            "rule": {
                "id": "100002",
                "level": 12,
                "description": "SSH Brute Force login followed by successful privilege escalation",
                "groups": ["authentication_failures", "mitre_t1110", "mitre_t1548"],
            },
            "agent": {"id": "1", "name": "server-prod-01"},
            "data": {
                "srcip": "198.51.100.45",
                "dstuser": "root",
                "dstport": "22",
                "protocol": "ssh",
                "action": "AUTH_SUCCESS_AFTER_BRUTEFORCE",
            },
            "full_log": (
                "Jun 05 10:00:01 server-prod-01 sshd[1234]: "
                "Accepted password for root from 198.51.100.45 port 51234 ssh2 "
                "(after 47 failed attempts)"
            ),
        }
    ],
}

_SIEM_C2 = {
    "status": "success",
    "hits": [
        {
            "@timestamp": "2026-06-05T10:05:33.000Z",
            "rule": {
                "id": "100003",
                "level": 14,
                "description": "Suspicious outbound traffic pattern — potential C2 beaconing",
                "groups": ["network_anomaly", "mitre_t1059", "mitre_t1071"],
            },
            "agent": {"id": "2", "name": "host-win10-08"},
            "data": {
                "srcip": "192.168.1.45",
                "dstip": "203.0.113.88",
                "dstport": "443",
                "process": "powershell.exe",
                "action": "OUTBOUND_HTTPS_SUSPICIOUS",
            },
            "full_log": (
                "Jun 05 10:05:33 host-win10-08 sysmon[8888]: "
                "Network connection detected: powershell.exe → 203.0.113.88:443 "
                "beacon_interval=60s total_bytes=1.2MB"
            ),
        }
    ],
}


class DummySiemProvider(ISiemProvider):
    """Fully simulated SIEM — used when SIEM_PROVIDER=dummy in .env."""

    async def query_logs(self, query: str, time_range: str = "last 1 hour") -> str:
        logger.info("provider.dummy_siem.query_logs", query=query, time_range=time_range)
        q = query.lower()

        if any(k in q for k in ("100002", "198.51.100.45", "bruteforce", "brute", "ssh", "8923", "agent.id:1")):
            result = _SIEM_BRUTE_FORCE
        elif any(k in q for k in ("100003", "203.0.113.88", "c2", "cobalt", "powershell", "beacon")):
            result = _SIEM_C2
        else:
            result = {"status": "success", "hits": []}

        hits = result["hits"]
        if not hits:
            return f"No events found for query '{query}' in {time_range}."

        lines = [f"Found {len(hits)} event(s):"]
        for h in hits:
            lines.append(
                f"[{h['@timestamp']}] Rule: {h['rule']['description']} "
                f"| Data: {json.dumps(h['data'])}"
            )
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Dummy Endpoint Provider
# ─────────────────────────────────────────────────────────────────────────────

_ENDPOINTS: dict[str, dict] = {
    "1": {
        "name": "server-prod-01",
        "ip": "192.168.10.1",
        "os": "Ubuntu 22.04 LTS",
        "status": "active",
        "version": "Wazuh v4.9.0",
        "groups": "linux-servers",
        "last_seen": "2026-06-05T10:00:01Z",
    },
    "2": {
        "name": "host-win10-08",
        "ip": "192.168.1.45",
        "os": "Windows 10 22H2",
        "status": "active",
        "version": "Wazuh v4.9.0",
        "groups": "windows-workstations",
        "last_seen": "2026-06-05T10:05:33Z",
    },
}


class DummyEndpointProvider(IEndpointProvider):
    """Fully simulated Endpoint provider — used when ENDPOINT_PROVIDER=dummy in .env."""

    async def get_endpoint_info(self, agent_id: str) -> str:
        logger.info("provider.dummy_endpoint.get_endpoint_info", agent_id=agent_id)
        ep = _ENDPOINTS.get(str(agent_id))
        if not ep:
            return f"Endpoint not found for agent ID: {agent_id} (Dummy provider)."
        return (
            f"Endpoint Info – ID: {agent_id}\n"
            f"  Hostname : {ep['name']}\n"
            f"  IP       : {ep['ip']}\n"
            f"  OS       : {ep['os']}\n"
            f"  Status   : {ep['status']}\n"
            f"  Version  : {ep['version']}\n"
            f"  Groups   : {ep['groups']}\n"
            f"  Last Seen: {ep['last_seen']}"
        )

    async def isolate_endpoint(self, agent_id: str) -> str:
        logger.info("provider.dummy_endpoint.isolate_endpoint", agent_id=agent_id)
        ep = _ENDPOINTS.get(str(agent_id))
        name = ep["name"] if ep else f"agent-{agent_id}"
        return (
            f"Active response command 'host-deny' broadcast to Wazuh agent {agent_id} ({name}) successfully. "
            f"(Dummy Endpoint Provider)"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Dummy Case Management Provider
# ─────────────────────────────────────────────────────────────────────────────

_CASE_COUNTER = 41009160


class DummyCaseManagementProvider(ICaseManagementProvider):
    """Fully simulated Case Management — used when CASE_MANAGEMENT_PROVIDER=dummy in .env."""

    async def create_case(
        self,
        title: str = "",
        description: str = "",
        severity: int = 2,
        tags: list[str] | None = None,
    ) -> str:
        global _CASE_COUNTER
        _CASE_COUNTER += 1
        case_id = f"~{_CASE_COUNTER}"
        logger.info("provider.dummy_case.create_case", title=title, case_id=case_id)
        return f"Case successfully created. Case ID: {case_id}"

    async def add_case_note(self, case_id: str, note: str, task_title: str = "Investigation Note") -> str:
        logger.info("provider.dummy_case.add_case_note", case_id=case_id)
        task_id = str(uuid.uuid4())[:8]
        return f"Note successfully added. Task ID: {task_id}"

    async def update_case_status(
        self, case_id: str, status: str, resolution_type: str = "TruePositive", summary: str = ""
    ) -> str:
        logger.info("provider.dummy_case.update_case_status", case_id=case_id, status=status)
        return f"Case {case_id} status updated to '{status}'. (Dummy Case Management Provider)"

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
        alert_id = f"~alert-{uuid.uuid4().hex[:8]}"
        logger.info("provider.dummy_case.create_alert", title=title, alert_id=alert_id)
        return f"Alert successfully created. Alert ID: {alert_id}"


# ─────────────────────────────────────────────────────────────────────────────
# Dummy Enrichment Provider
# ─────────────────────────────────────────────────────────────────────────────

_IP_INTEL: dict[str, dict] = {
    "198.51.100.45": {
        "verdict": "malicious",
        "score": 88,
        "country": "RU",
        "tags": ["ssh-brute-force", "botnet"],
        "engines": "AbuseIPDB (score: 88/100), VirusTotal (9/94 engines flagged)",
    },
    "203.0.113.88": {
        "verdict": "malicious",
        "score": 95,
        "country": "CN",
        "tags": ["cobalt-strike-c2", "apt"],
        "engines": "VirusTotal (78/94 engines flagged — Cobalt Strike C2), AbuseIPDB (score: 95/100)",
    },
}


class DummyEnrichmentProvider(IEnrichmentProvider):
    """Fully simulated Enrichment provider — used when ENRICHMENT_PROVIDER=dummy in .env."""

    async def get_ip_reputation(self, ip_address: str) -> str:
        logger.info("provider.dummy_enrichment.get_ip_reputation", ip_address=ip_address)
        intel = _IP_INTEL.get(ip_address)
        if intel:
            return (
                f"IP Reputation for {ip_address}:\n"
                f"  Verdict : {intel['verdict'].upper()}\n"
                f"  Score   : {intel['score']}/100\n"
                f"  Country : {intel['country']}\n"
                f"  Tags    : {', '.join(intel['tags'])}\n"
                f"  Engines : {intel['engines']}"
            )
        return (
            f"IP Reputation for {ip_address}:\n"
            f"  Verdict : clean\n"
            f"  Score   : 0/100\n"
            f"  Engines : AbuseIPDB (score: 0/100), VirusTotal (0/94 engines flagged)"
        )

    async def get_file_reputation(self, file_hash: str) -> str:
        logger.info("provider.dummy_enrichment.get_file_reputation", file_hash=file_hash)
        return (
            f"File Hash Reputation for {file_hash}:\n"
            f"  Verdict : clean\n"
            f"  Score   : 0/100\n"
            f"  Engines : VirusTotal (0/94 engines flagged) (Dummy Enrichment Provider)"
        )

    async def get_domain_url_reputation(self, url_or_domain: str) -> str:
        logger.info("provider.dummy_enrichment.get_domain_url_reputation", url_or_domain=url_or_domain)
        return (
            f"Domain/URL Reputation for {url_or_domain}:\n"
            f"  Verdict : clean\n"
            f"  Score   : 0/100\n"
            f"  Engines : VirusTotal (0/94 engines flagged) (Dummy Enrichment Provider)"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Dummy Firewall Provider
# ─────────────────────────────────────────────────────────────────────────────

class DummyFirewallProvider(IFirewallProvider):
    async def block_ip(self, ip_address: str) -> str:
        logger.info("provider.firewall.block_ip", ip_address=ip_address)
        fw_url = os.getenv("FIREWALL_API_URL", "")
        fw_key = os.getenv("FIREWALL_API_KEY", "")

        if not fw_url:
            return f"Malicious IP {ip_address} blocked at perimeter firewall successfully. (Dummy Firewall Provider)"

        headers = {"Authorization": f"Bearer {fw_key}"}
        try:
            async with httpx.AsyncClient() as client:
                payload = {"action": "block", "ip": ip_address}
                resp = await client.post(f"{fw_url}/api/rules/block", json=payload, headers=headers, timeout=10.0)
                resp.raise_for_status()
                return f"IP {ip_address} blocked on firewall."
        except Exception as e:
            return f"Error blocking IP: {str(e)}"


# ─────────────────────────────────────────────────────────────────────────────
# Dummy IAM Provider
# ─────────────────────────────────────────────────────────────────────────────

class DummyIamProvider(IIamProvider):
    async def get_user_info(self, username: str) -> str:
        logger.info("provider.iam.get_user_info", username=username)
        idm_url = os.getenv("IDM_API_URL", "")
        idm_key = os.getenv("IDM_API_KEY", "")

        if not idm_url:
            return f"IDM_API_URL is not configured. Dummy Data → User: {username} | Role: Standard | Status: Active"

        headers = {"Authorization": f"Bearer {idm_key}"}
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(f"{idm_url}/api/users/{username}", headers=headers, timeout=10.0)
                resp.raise_for_status()
                return f"User Info for {username}: {json.dumps(resp.json())}"
        except Exception as e:
            return f"Error getting user info: {str(e)}"

    async def disable_user_account(self, username: str) -> str:
        logger.info("provider.iam.disable_user_account", username=username)
        idm_url = os.getenv("IDM_API_URL", "")
        idm_key = os.getenv("IDM_API_KEY", "")

        if not idm_url:
            return f"IDM_API_URL not configured. Dummy action: User account {username} disabled."

        headers = {"Authorization": f"Bearer {idm_key}"}
        try:
            async with httpx.AsyncClient() as client:
                payload = {"status": "disabled", "reason": "Security Incident"}
                resp = await client.put(
                    f"{idm_url}/api/users/{username}/status", json=payload, headers=headers, timeout=10.0
                )
                resp.raise_for_status()
                return f"User account {username} disabled successfully."
        except Exception as e:
            return f"Error disabling user account: {str(e)}"


# ─────────────────────────────────────────────────────────────────────────────
# Dummy SOAR Provider
# ─────────────────────────────────────────────────────────────────────────────

class DummySoarProvider(ISoarProvider):
    async def trigger_workflow(
        self, workflow_id: str, data: dict | None = None, webhook_url: str = ""
    ) -> str:
        logger.info("provider.soar.trigger_workflow", workflow_id=workflow_id, data=data)
        return f"SOAR workflow '{workflow_id}' triggered successfully (Dummy SOAR Provider)."
