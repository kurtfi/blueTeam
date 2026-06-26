"""
Extracts MITRE ATT&CK Technique IDs from Mordor zip/json paths and filenames.
"""

import json
import os
import re

# Static filename mapping for common Mordor files (fallback)
FILENAME_TO_MITRE = {
    "empire_dcsync_dcerpc_drsuapi_dsgetncchanges": "T1003.006",
    "cmd_dumping_ntds_dit_file_ntdsutil": "T1003.003",
    "cmd_dumping_ntds_dit_file_volume_shadow_copy": "T1003.003",
    "cmd_lsass_memory_dumpert": "T1003.001",
    "cmd_sam_copy_esentutl": "T1003.002",
    "covenant_wmi_wbemcomn_dll_hijack": "T1021.002",  # WMI/SMB Admin Shares
    "empire_launcher_vbs": "T1059",
    "empire_persistence_registry_modification_run_keys_elevated_user": "T1547.001",
    "empire_persistence_registry_modification_run_keys_standard_user": "T1547.001",
    "psh_powershell_httplistener": "T1071.001",
    "empire_uac_shellapi_fodhelper": "T1548.002",
    "sh_binary_padding_dd": "T1562.001",
    "sh_arp_cache": "T1016",
    "ec2_proxy_s3_exfiltration": "T1048",
    "aws_s3_honeybucketlogs": "T1046",
    "appsimulator_cobaltstrike": "T1071.001",
}

# Regex to extract MITRE technique ID (Txxxx or Txxxx.xxx)
MITRE_PATTERN = re.compile(r"(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)

# Load compiled mappings if present
current_dir = os.path.dirname(os.path.abspath(__file__))
mappings_file = os.path.join(current_dir, "mordor_mappings.json")
MORDOR_MAPPINGS = {}
if os.path.exists(mappings_file):
    try:
        with open(mappings_file, encoding="utf-8") as f:
            MORDOR_MAPPINGS = json.load(f)
    except Exception:
        pass


def get_mordor_file_info(filepath: str) -> dict | None:
    """
    Looks up metadata details for a given file name from the compiled mapping.
    """
    filename = os.path.basename(filepath).lower()
    return MORDOR_MAPPINGS.get(filename)


def extract_technique_from_path(filepath: str) -> str:
    """
    Given a file path or name, extracts the MITRE ATT&CK Technique ID.
    Example:
        "/data/small/windows/credential_access/host/cmd_lsass_memory_dumpert.zip" -> "T1003.001"
    """
    filename = os.path.basename(filepath)

    # 1. Look up in compiled JSON mappings
    info = get_mordor_file_info(filename)
    if info and info.get("techniques"):
        return info["techniques"][0]

    name_without_ext = os.path.splitext(filename)[0].lower()

    # 2. Exact match on static filename mapping (without extension)
    if name_without_ext in FILENAME_TO_MITRE:
        return FILENAME_TO_MITRE[name_without_ext]

    # 3. Check if the name matches a prefix in our static mapping
    for key, technique in FILENAME_TO_MITRE.items():
        if key in name_without_ext or name_without_ext in key:
            return technique

    # 4. Use regex to search for explicit T-ID in the full filepath
    matches = MITRE_PATTERN.findall(filepath)
    if matches:
        return matches[-1].upper()  # return the last match or most specific one

    # 5. Fallback based on tactic folder in path
    normalized_path = filepath.lower().replace("\\", "/")
    if "credential_access" in normalized_path:
        return "T1003"  # General Credential Dumping
    elif "lateral_movement" in normalized_path:
        return "T1021"  # General Remote Services
    elif "defense_evasion" in normalized_path:
        return "T1562"  # General Impair Defenses
    elif "execution" in normalized_path:
        return "T1059"  # General Command Interpreter
    elif "persistence" in normalized_path:
        return "T1547"  # General Registry Run keys
    elif "discovery" in normalized_path:
        return "T1082"  # General System Info Discovery

    return "T1059"  # Fallback to execution/command interpreter
