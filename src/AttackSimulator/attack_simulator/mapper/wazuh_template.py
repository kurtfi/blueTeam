"""
Generates structured Wazuh alert payloads from MITRE Techniques and raw events.
"""

from datetime import datetime, UTC
from typing import Any
from attack_simulator.mapper.mitre_catalog import get_mitre_info

# Static rule templates for MITRE techniques
TECHNIQUE_RULES = {
    "T1003.001": {
        "rule_id": "100002",
        "level": 12,
        "description": "LSASS memory dumping detected via Sysmon Process Access",
        "groups": ["sysmon", "lsass", "credential_access", "mitre_t1003"],
    },
    "T1003.002": {
        "rule_id": "100003",
        "level": 10,
        "description": "SAM database extraction attempt",
        "groups": ["windows", "sam", "credential_access", "mitre_t1003"],
    },
    "T1003.003": {
        "rule_id": "100004",
        "level": 11,
        "description": "NTDS.dit dumping attempt via Volume Shadow Copy or ntdsutil",
        "groups": ["windows", "ntds", "credential_access", "mitre_t1003"],
    },
    "T1003.006": {
        "rule_id": "100005",
        "level": 12,
        "description": "Active Directory DCSync credential replication (T1003.006)",
        "groups": ["windows", "active_directory", "credential_access", "mitre_t1003"],
    },
    "T1110": {
        "rule_id": "5712",
        "level": 10,
        "description": "Multiple failed login attempts - potential SSH Brute Force",
        "groups": ["authentication_failed", "brute_force", "mitre_t1110"],
    },
    "T1021.002": {
        "rule_id": "100010",
        "level": 9,
        "description": "Windows Admin Share SMB connection (T1021.002)",
        "groups": ["windows", "smb", "lateral_movement", "mitre_t1021"],
    },
    "T1047": {
        "rule_id": "100012",
        "level": 8,
        "description": "Windows Management Instrumentation (WMI) execution (T1047)",
        "groups": ["windows", "wmi", "execution", "mitre_t1047"],
    },
    "T1059.004": {
        "rule_id": "100015",
        "level": 6,
        "description": "Suspicious Unix Shell interpreter execution",
        "groups": ["linux", "shell", "execution", "mitre_t1059"],
    },
    "T1059.001": {
        "rule_id": "100016",
        "level": 7,
        "description": "Suspicious PowerShell command execution",
        "groups": ["windows", "powershell", "execution", "mitre_t1059"],
    },
    "T1548.001": {
        "rule_id": "100020",
        "level": 9,
        "description": "Setuid/Setgid binary modification detected",
        "groups": ["linux", "privilege_escalation", "mitre_t1548"],
    },
    "T1048": {
        "rule_id": "100025",
        "level": 10,
        "description": "Data exfiltration over alternative protocol (T1048)",
        "groups": ["network", "exfiltration", "mitre_t1048"],
    },
    "T1562.001": {
        "rule_id": "100030",
        "level": 8,
        "description": "Disable/Modify security tools (T1562.001)",
        "groups": ["windows", "impair_defenses", "defense_evasion", "mitre_t1562"],
    },
}


def generate_wazuh_alert(technique_id: str, raw_event: dict[str, Any] | None = None) -> dict[str, Any]:
    """
    Combines a MITRE technique rule template with raw event fields to output a standard Wazuh alert.
    """
    raw_event = raw_event or {}
    mitre_info = get_mitre_info(technique_id)
    
    # Resolve rule template for the technique
    template = TECHNIQUE_RULES.get(technique_id)
    if not template:
        # Fallback dynamic template
        template = {
            "rule_id": "999999",
            "level": 5,
            "description": f"MITRE ATT&CK {technique_id} - {mitre_info['name']} detected",
            "groups": ["mitre", f"mitre_{technique_id.lower().replace('.', '_')}"],
        }

    # Extract source IP and target user from raw event
    src_ip = (
        raw_event.get("IpAddress")
        or raw_event.get("SourceIp")
        or raw_event.get("srcip")
        or raw_event.get("IpAddress")
        or "10.0.2.15"  # default local subnet IP
    )
    dst_user = (
        raw_event.get("User")
        or raw_event.get("TargetUserName")
        or raw_event.get("dstuser")
        or "SYSTEM"
    )
    
    timestamp = raw_event.get("TimeCreated") or raw_event.get("@timestamp")
    if not timestamp:
        timestamp = datetime.now(UTC).isoformat()
        
    full_log_str = raw_event.get("CommandLine") or raw_event.get("message")
    if not full_log_str:
        # Serialise raw event if no specific log message
        full_log_str = f"Sysmon Event ID {raw_event.get('EventID', 'N/A')}: " + ", ".join(
            f"{k}={v}" for k, v in list(raw_event.items())[:5]
        )

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
                "tactic": [mitre_info["tactic"]],
            }
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
