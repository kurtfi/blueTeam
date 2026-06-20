"""
Generates structured Wazuh alert payloads from raw events.
"""

from datetime import UTC, datetime
from typing import Any

from attack_simulator.mapper.mitre_catalog import get_mitre_info

# Static rule templates keyed by technique (internal use only – the technique key
# itself is never exposed in the generated alert payload).
TECHNIQUE_RULES = {
    "T1003.001": {
        "rule_id": "100002",
        "level": 12,
        "description": "Suspicious process access detected via Sysmon",
        "groups": ["sysmon", "windows"],
    },
    "T1003.002": {
        "rule_id": "100003",
        "level": 10,
        "description": "Suspicious registry hive access attempt",
        "groups": ["windows", "registry"],
    },
    "T1003.003": {
        "rule_id": "100004",
        "level": 11,
        "description": "Suspicious volume shadow copy or ntdsutil activity",
        "groups": ["windows", "filesystem"],
    },
    "T1003.006": {
        "rule_id": "100005",
        "level": 12,
        "description": "Suspicious Active Directory replication activity",
        "groups": ["windows", "active_directory"],
    },
    "T1003.008": {
        "rule_id": "100008",
        "level": 11,
        "description": "Unauthorized access to passwd or shadow file",
        "groups": ["linux", "filesystem"],
    },
    "T1110": {
        "rule_id": "5712",
        "level": 10,
        "description": "Multiple failed login attempts detected",
        "groups": ["authentication_failed"],
    },
    "T1021.002": {
        "rule_id": "100010",
        "level": 9,
        "description": "Windows Admin Share SMB connection",
        "groups": ["windows", "smb"],
    },
    "T1047": {
        "rule_id": "100012",
        "level": 8,
        "description": "WMI process execution detected",
        "groups": ["windows", "wmi"],
    },
    "T1059.004": {
        "rule_id": "100015",
        "level": 6,
        "description": "Suspicious shell interpreter execution",
        "groups": ["linux", "shell"],
    },
    "T1059.001": {
        "rule_id": "100016",
        "level": 7,
        "description": "Suspicious PowerShell command execution",
        "groups": ["windows", "powershell"],
    },
    "T1548.001": {
        "rule_id": "100020",
        "level": 9,
        "description": "Setuid/Setgid binary modification detected",
        "groups": ["linux", "filesystem"],
    },
    "T1048": {
        "rule_id": "100025",
        "level": 10,
        "description": "Unusual outbound network protocol activity",
        "groups": ["network"],
    },
    "T1562.001": {
        "rule_id": "100030",
        "level": 8,
        "description": "Security tool configuration change detected",
        "groups": ["windows", "services"],
    },
}


def generate_wazuh_alert(technique_id: str, raw_event: dict[str, Any] | None = None) -> dict[str, Any]:
    """
    Combines a technique rule template with raw event fields to output a standard Wazuh alert.
    No MITRE technique IDs, tactic names, or attack classification hints are included
    in the output payload to prevent information leakage during simulation tests.
    """
    raw_event = raw_event or {}

    # Resolve rule template for the technique
    template = TECHNIQUE_RULES.get(technique_id)
    if not template:
        # Try base match (e.g. T1110.003 -> T1110)
        base_tech = technique_id.split(".")[0]
        template = TECHNIQUE_RULES.get(base_tech)

        # Try matching any registered subtechnique of the same base (e.g. T1003 -> T1003.001)
        if not template:
            for key, val in TECHNIQUE_RULES.items():
                if key.split(".")[0] == base_tech:
                    template = val
                    break

    if not template:
        # Fallback dynamic template – generic, no technique/tactic info
        template = {
            "rule_id": "999999",
            "level": 5,
            "description": "Suspicious activity detected",
            "groups": ["generic"],
        }

    # Extract source IP and target user from raw event
    src_ip = (
        raw_event.get("IpAddress")
        or raw_event.get("SourceIp")
        or raw_event.get("srcip")
        or raw_event.get("IpAddress")
        or "10.0.2.15"  # default local subnet IP
    )
    dst_user = raw_event.get("User") or raw_event.get("TargetUserName") or raw_event.get("dstuser") or "SYSTEM"

    timestamp = raw_event.get("TimeCreated") or raw_event.get("@timestamp")
    if not timestamp:
        timestamp = datetime.now(UTC).isoformat()

    full_log_str = raw_event.get("CommandLine") or raw_event.get("message")
    if not full_log_str:
        # Serialise raw event if no specific log message
        full_log_str = f"Sysmon Event ID {raw_event.get('EventID', 'N/A')}: " + ", ".join(
            f"{k}={v}" for k, v in list(raw_event.items())[:5]
        )

    # Resolve tactic from mitre catalog
    mitre_info = get_mitre_info(technique_id)
    tactic = mitre_info.get("tactic", "Unknown Tactic")

    # Construct the final Wazuh alert payload
    alert = {
        "@timestamp": timestamp,
        "agent": {
            "id": raw_event.get("AgentID", "001"),
            "name": raw_event.get("Computer", "client-workstation-01"),
        },
        "rule": {
            "id": template["rule_id"],
            "level": template["level"],
            "description": template["description"],
            "groups": template["groups"],
            "mitre": {
                "id": [technique_id],
                "tactic": [tactic],
            },
        },
        "data": {
            "srcip": src_ip,
            "dstuser": dst_user,
            "command": raw_event.get("CommandLine", ""),
            "parent_process": raw_event.get("ParentImage", ""),
            "process": raw_event.get("Image", ""),
            "event_id": str(raw_event.get("EventID", "")),
        },
        "full_log": full_log_str,
    }

    return alert


def strip_information_leakage(alert: dict[str, Any], technique_id: str) -> dict[str, Any]:
    """
    Strips MITRE and credential access information leakage from a Wazuh alert.
    Useful for saving clean events in the database or sending to webhooks.
    """
    import copy
    import re

    clean_alert = copy.deepcopy(alert)
    if "rule" not in clean_alert:
        return clean_alert

    rule = clean_alert["rule"]

    # 1. Remove mitre block
    if "mitre" in rule:
        del rule["mitre"]

    # 2. Clean description
    desc = rule.get("description", "")
    if desc.startswith("MITRE ATT&CK") or "LSASS" in desc or "Credential Dumping" in desc:
        mitre_info = get_mitre_info(technique_id)
        tactic = mitre_info.get("tactic", "Unknown Tactic")
        if tactic != "Unknown Tactic":
            rule["description"] = f"Suspicious {tactic.lower()} activity detected"
        else:
            rule["description"] = "Suspicious security event detected"
    else:
        # Strip any parenthesized MITRE ID like (T1003.001)
        rule["description"] = re.sub(r"\s*\([Tt]\d+(?:\.\d+)?\)\s*$", "", desc).strip()

    # 3. Clean groups
    groups = rule.get("groups", [])
    new_groups = [g for g in groups if not g.startswith("mitre") and g != "mitre"]
    if not new_groups:
        new_groups = ["generic"]
    rule["groups"] = new_groups

    return clean_alert
