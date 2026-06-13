"""
Static lookup catalog for MITRE ATT&CK tactics and techniques.
"""

MITRE_CATALOG = {
    # Credential Access
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
    },
    "T1003.001": {
        "name": "LSASS Memory",
        "tactic": "Credential Access",
    },
    "T1003.002": {
        "name": "Security Account Manager",
        "tactic": "Credential Access",
    },
    "T1003.003": {
        "name": "NTDS",
        "tactic": "Credential Access",
    },
    "T1003.006": {
        "name": "DCSync",
        "tactic": "Credential Access",
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
    },
    "T1110.001": {
        "name": "Password Guessing",
        "tactic": "Credential Access",
    },
    "T1558": {
        "name": "Steal or Abuse Kerberos Tickets",
        "tactic": "Credential Access",
    },
    "T1558.003": {
        "name": "Kerberoasting",
        "tactic": "Credential Access",
    },

    # Privilege Escalation
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
    },
    "T1548.001": {
        "name": "Setuid and Setgid",
        "tactic": "Privilege Escalation",
    },
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
    },

    # Defense Evasion
    "T1562": {
        "name": "Impair Defenses",
        "tactic": "Defense Evasion",
    },
    "T1562.001": {
        "name": "Disable or Modify Tools",
        "tactic": "Defense Evasion",
    },
    "T1070": {
        "name": "Indicator Removal",
        "tactic": "Defense Evasion",
    },
    "T1070.001": {
        "name": "Clear Windows Event Logs",
        "tactic": "Defense Evasion",
    },

    # Lateral Movement
    "T1021": {
        "name": "Remote Services",
        "tactic": "Lateral Movement",
    },
    "T1021.001": {
        "name": "Remote Desktop Protocol",
        "tactic": "Lateral Movement",
    },
    "T1021.002": {
        "name": "SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
    },
    "T1047": {
        "name": "Windows Management Instrumentation",
        "tactic": "Execution",
    },

    # Command and Control
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
    },
    "T1071.001": {
        "name": "Web Protocols",
        "tactic": "Command and Control",
    },

    # Exfiltration
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
    },

    # Execution
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
    },
    "T1059.004": {
        "name": "Unix Shell",
        "tactic": "Execution",
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution",
    },
}


def get_mitre_info(technique_id: str) -> dict[str, str]:
    """
    Get name and tactic for a technique. Fallback if not mapped.
    """
    cleaned_id = technique_id.upper().strip()
    if cleaned_id in MITRE_CATALOG:
        return MITRE_CATALOG[cleaned_id]
        
    # If it is a sub-technique (e.g. T1003.001), try parent technique
    if "." in cleaned_id:
        parent_id = cleaned_id.split(".")[0]
        if parent_id in MITRE_CATALOG:
            return {
                "name": f"{MITRE_CATALOG[parent_id]['name']} (Sub-technique)",
                "tactic": MITRE_CATALOG[parent_id]["tactic"]
            }
            
    return {
        "name": f"Technique {technique_id}",
        "tactic": "Unknown Tactic"
    }
