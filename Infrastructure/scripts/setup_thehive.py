"""
TheHive MITRE ATT&CK Setup Script
===================================
Creates Case Templates for MITRE ATT&CK scenarios.

Authenticates as:
  - admin@thehive.local via API key (THEHIVE_ADMIN_API_KEY env var)
    OR falls back to session-cookie login with admin@thehive.local / secret
  - analyst via THEHIVE_API_KEY (for connectivity verification)
"""

import os
import sys

import httpx
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

THEHIVE_URL = os.getenv("THEHIVE_URL", "http://localhost:9000")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY", "")
THEHIVE_ADMIN_API_KEY = os.getenv("THEHIVE_ADMIN_API_KEY", "+ci6e8evJctFtTBq0WZWIXltfC1T6EKp")
THEHIVE_SOC_ADMIN_KEY = os.getenv("THEHIVE_SOC_ADMIN_KEY", "/j88/hhivDtRCWAHpi66H3ZydtPKTpyK")
THEHIVE_ADMIN_USER = "admin@thehive.local"
THEHIVE_ADMIN_PASS = "secret"

ANALYST_API_HEADERS = {
    "Authorization": f"Bearer {THEHIVE_API_KEY}",
    "X-Organisation": "asdg",
    "Content-Type": "application/json",
}

# ─────────────────────────────────────────────────────────────
# Case Templates for MITRE ATT&CK Scenarios
# ─────────────────────────────────────────────────────────────
TEMPLATES = [
    {
        "name": "MITRE T1003.008 - OS Credential Dumping",
        "titlePrefix": "[MITRE T1003.008] ",
        "description": (
            "### MITRE ATT&CK T1003.008 – OS Credential Dumping (/etc/shadow)\n\n"
            "Triggered when an unauthorized process attempts to read or copy `/etc/shadow`, "
            "indicating possible credential harvesting.\n\n"
            "**Detection Source:** Wazuh custom rule 100002\n\n"
            "### Recommended Actions\n"
            "1. Identify the process and user that initiated the read request.\n"
            "2. Isolate the affected endpoint via Wazuh Active Response (`host-deny`).\n"
            "3. Enrich file hashes and source IPs via Cortex / VirusTotal.\n"
            "4. Rotate compromised credentials immediately.\n"
            "5. Check for lateral movement indicators."
        ),
        "severity": 3,
        "tlp": 2,
        "pap": 2,
        "tags": ["mitre", "t1003", "t1003.008", "credential-dumping", "agentix-sim"],
        "tasks": [
            {
                "title": "Analyze Process & Execution Tree",
                "description": "Identify parent process, command-line arguments, and user context via Wazuh dashboard.",
                "group": "Investigation",
                "order": 0,
            },
            {
                "title": "Run Cortex VirusTotal Analyzer",
                "description": "Submit file hashes or destination IPs to Cortex VirusTotal analyzer.",
                "group": "Enrichment",
                "order": 1,
            },
            {
                "title": "Verify Endpoint Isolation",
                "description": "Confirm that Wazuh Active Response `host-deny` executed successfully on the target agent.",
                "group": "Containment",
                "order": 2,
            },
            {
                "title": "Reset Compromised Credentials",
                "description": "Rotate passwords for all accounts accessible on the compromised host.",
                "group": "Remediation",
                "order": 3,
            },
            {
                "title": "Post-Incident Review",
                "description": "Document root cause, timeline, and lessons learned.",
                "group": "Reporting",
                "order": 4,
            },
        ],
    },
    {
        "name": "MITRE T1059.004 - Suspicious Command Execution",
        "titlePrefix": "[MITRE T1059.004] ",
        "description": (
            "### MITRE ATT&CK T1059.004 – Suspicious Unix Shell Execution\n\n"
            "Triggered when a reverse-shell pattern, unusual bash redirect, or "
            "netcat listener is detected on a monitored host.\n\n"
            "**Detection Source:** Wazuh custom rule 100003\n\n"
            "### Recommended Actions\n"
            "1. Inspect command lines and active network connections (`netstat`).\n"
            "2. Check for web shells or persistence mechanisms (cron, `.bashrc`).\n"
            "3. Isolate the host to prevent data exfiltration.\n"
            "4. Capture forensic evidence before remediation."
        ),
        "severity": 3,
        "tlp": 2,
        "pap": 2,
        "tags": ["mitre", "t1059", "t1059.004", "execution", "reverse-shell", "agentix-sim"],
        "tasks": [
            {
                "title": "Examine Network Connections",
                "description": "Identify external connections initiated by the suspicious command.",
                "group": "Investigation",
                "order": 0,
            },
            {
                "title": "Check Host Persistence Mechanisms",
                "description": "Scan cron jobs, user additions, `.bashrc`, and modified system binaries.",
                "group": "Investigation",
                "order": 1,
            },
            {
                "title": "Isolate Endpoint",
                "description": "Block external network access via Wazuh Active Response.",
                "group": "Containment",
                "order": 2,
            },
            {
                "title": "Capture Forensic Artefacts",
                "description": "Collect memory dump, running processes, and open file handles before cleanup.",
                "group": "Forensics",
                "order": 3,
            },
        ],
    },
    # ──────────────────────────────────────────────────────────────────────────
    # PB-003  T1110 – Brute Force Attack
    # ──────────────────────────────────────────────────────────────────────────
    {
        "name": "MITRE T1110 - Brute Force Attack",
        "titlePrefix": "[MITRE T1110] ",
        "description": (
            "### MITRE ATT&CK T1110 – Brute Force / Password Spray\n\n"
            "Multiple failed authentication attempts from a single source indicate "
            "a brute force or password spray attack. Assess whether any attempt "
            "succeeded before escalating containment.\n\n"
            "**Detection Source:** Wazuh rules 5710/5712/2501/2502\n\n"
            "### Recommended Actions\n"
            "1. Count failed attempts per source IP in last 15 minutes.\n"
            "2. **CRITICAL**: Check for any successful login from the same source.\n"
            "3. Enrich source IP via Cortex VirusTotal.\n"
            "4. Block source IP at perimeter firewall.\n"
            "5. Lock targeted account if a successful login was detected."
        ),
        "severity": 2,
        "tlp": 2,
        "pap": 2,
        "tags": ["mitre", "t1110", "brute-force", "authentication", "agentix"],
        "tasks": [
            {
                "title": "Analyse Authentication Failure Volume",
                "description": "Count failed auth attempts per source IP; extract targeted usernames.",
                "group": "Investigation",
                "order": 0,
            },
            {
                "title": "Check for Successful Login After Failures",
                "description": "Query SIEM for successful auth from same source IP within 5 min of last failure.",
                "group": "Investigation",
                "order": 1,
            },
            {
                "title": "Enrich Source IP via Cortex",
                "description": "Submit attacker IP to VirusTotal analyzer in Cortex.",
                "group": "Enrichment",
                "order": 2,
            },
            {
                "title": "Block Attacker IP",
                "description": "Block brute force source IP at perimeter firewall. Verify not a legitimate admin host.",
                "group": "Containment",
                "order": 3,
            },
            {
                "title": "Lock Compromised Account (if applicable)",
                "description": "Disable the targeted account via IAM/AD if a successful login was detected.",
                "group": "Containment",
                "order": 4,
            },
            {
                "title": "Post-Incident Review",
                "description": "Document IP, failure count, success status, and actions taken.",
                "group": "Reporting",
                "order": 5,
            },
        ],
    },
    # ──────────────────────────────────────────────────────────────────────────
    # PB-004  T1550.002 – Pass-the-Hash / Lateral Movement
    # ──────────────────────────────────────────────────────────────────────────
    {
        "name": "MITRE T1550.002 - Pass-the-Hash / Lateral Movement",
        "titlePrefix": "[MITRE T1550.002] ",
        "description": (
            "### MITRE ATT&CK T1550.002 – Pass-the-Hash\n\n"
            "NTLM hash reuse or anomalous lateral movement detected between "
            "internal hosts. The attacker may have stolen credentials from a "
            "previous compromise and is pivoting through the network.\n\n"
            "**Detection Source:** Wazuh Windows rules (EventID 4624/4648, logon type 3)\n\n"
            "### Recommended Actions\n"
            "1. Map the lateral movement path (source host → destination host).\n"
            "2. Identify which account/hash was used.\n"
            "3. Isolate the source host.\n"
            "4. Force password reset for the compromised account.\n"
            "5. Escalate to DFIR for full credential audit."
        ),
        "severity": 4,
        "tlp": 2,
        "pap": 2,
        "tags": ["mitre", "t1550", "t1550.002", "pass-the-hash", "lateral-movement", "agentix"],
        "tasks": [
            {
                "title": "Map Lateral Movement Path",
                "description": "Trace auth chain: source host → destination host(s) using SIEM Windows event logs.",
                "group": "Investigation",
                "order": 0,
            },
            {
                "title": "Identify Compromised Account & Hash",
                "description": "Determine which domain account NTLM hash was reused. Check EventID 4624 logon type 3.",
                "group": "Investigation",
                "order": 1,
            },
            {
                "title": "Retrieve Wazuh Agent Details for Affected Hosts",
                "description": "Get hostname, OS, and last-seen for each host in the lateral movement chain.",
                "group": "Investigation",
                "order": 2,
            },
            {
                "title": "Isolate Source Host",
                "description": "Apply Wazuh host-deny active response to the originating host.",
                "group": "Containment",
                "order": 3,
            },
            {
                "title": "Force Password Reset for Compromised Account",
                "description": "Disable account via AD and require immediate password reset to invalidate hash.",
                "group": "Remediation",
                "order": 4,
            },
            {
                "title": "DFIR Escalation",
                "description": "Escalate to DFIR for memory forensics, NTDS.dit assessment, and Kerberoasting sweep.",
                "group": "Reporting",
                "order": 5,
            },
        ],
    },
    # ──────────────────────────────────────────────────────────────────────────
    # PB-005  T1048 – Data Exfiltration via DNS
    # ──────────────────────────────────────────────────────────────────────────
    {
        "name": "MITRE T1048 - Data Exfiltration via DNS",
        "titlePrefix": "[MITRE T1048] ",
        "description": (
            "### MITRE ATT&CK T1048.003 – Exfiltration Over Alternative Protocol: DNS\n\n"
            "Anomalous DNS query volume or long/encoded DNS queries detected, "
            "indicating possible data exfiltration via DNS tunneling "
            "(e.g. iodine, dnscat2).\n\n"
            "**Detection Source:** Wazuh network traffic monitoring\n\n"
            "### Recommended Actions\n"
            "1. Identify the DNS tunnel destination domain.\n"
            "2. Estimate volume of data exfiltrated.\n"
            "3. Enrich destination domain via Cortex.\n"
            "4. Block DNS tunnel at firewall / DNS sinkhole.\n"
            "5. Notify DPO if sensitive data confirmed exfiltrated."
        ),
        "severity": 3,
        "tlp": 2,
        "pap": 2,
        "tags": ["mitre", "t1048", "t1048.003", "exfiltration", "dns-tunneling", "agentix"],
        "tasks": [
            {
                "title": "Identify DNS Tunnel Destination",
                "description": "Extract suspicious DNS domain from SIEM. Look for long subdomains or high query rates.",
                "group": "Investigation",
                "order": 0,
            },
            {
                "title": "Estimate Exfiltrated Data Volume",
                "description": "Calculate total DNS query payload bytes over detection window.",
                "group": "Investigation",
                "order": 1,
            },
            {
                "title": "Enrich Destination Domain via Cortex",
                "description": "Submit DNS destination domain to VirusTotal/PassiveDNS analyzer.",
                "group": "Enrichment",
                "order": 2,
            },
            {
                "title": "Block DNS Tunnel at Firewall",
                "description": "Block destination IP and add domain to DNS sinkhole. Coordinate with network team.",
                "group": "Containment",
                "order": 3,
            },
            {
                "title": "Data Breach Assessment & DPO Notification",
                "description": "Assess if PII/sensitive data was exfiltrated. Notify DPO if required by regulation.",
                "group": "Reporting",
                "order": 4,
            },
        ],
    },
    # ──────────────────────────────────────────────────────────────────────────
    # PB-006  T1486 – Ransomware / Data Encrypted for Impact
    # ──────────────────────────────────────────────────────────────────────────
    {
        "name": "MITRE T1486 - Ransomware / Data Encrypted for Impact",
        "titlePrefix": "[MITRE T1486] 🚨 ",
        "description": (
            "### MITRE ATT&CK T1486 – Data Encrypted for Impact (Ransomware)\n\n"
            "Mass file modification, rename events, or ransom note creation detected. "
            "This is a **P0 INCIDENT**. Immediate isolation is required — do not "
            "wait for enrichment.\n\n"
            "**Detection Source:** Wazuh syscheck (mass file modification events)\n\n"
            "### Recommended Actions\n"
            "1. **IMMEDIATELY isolate the affected host** — do not wait.\n"
            "2. Identify ransomware process and family.\n"
            "3. Determine blast radius (how many files/hosts affected).\n"
            "4. Block C2 IP if identified.\n"
            "5. Assess backup integrity and initiate DR."
        ),
        "severity": 4,
        "tlp": 2,
        "pap": 2,
        "tags": ["mitre", "t1486", "ransomware", "p0", "active-incident", "agentix"],
        "tasks": [
            {
                "title": "🚨 IMMEDIATE: Isolate Affected Host",
                "description": "Apply Wazuh host-deny active response NOW. Time is critical.",
                "group": "Containment",
                "order": 0,
            },
            {
                "title": "Determine Scope of File Encryption",
                "description": "Count total file modification events; identify encrypted extensions and ransom notes.",
                "group": "Investigation",
                "order": 1,
            },
            {
                "title": "Identify Ransomware Process & Family",
                "description": "Find the process responsible. Submit file hash to Cortex VirusTotal.",
                "group": "Investigation",
                "order": 2,
            },
            {
                "title": "Block Ransomware C2",
                "description": "If C2 IP/domain is identified, block at perimeter firewall.",
                "group": "Containment",
                "order": 3,
            },
            {
                "title": "Backup Restore Assessment",
                "description": "Contact DR team: last clean backup, RTO, and whether backups are also encrypted.",
                "group": "Remediation",
                "order": 4,
            },
            {
                "title": "Executive & Legal Notification",
                "description": "Notify CISO, legal, and communications team. Assess regulatory reporting obligations.",
                "group": "Reporting",
                "order": 5,
            },
        ],
    },
    # ──────────────────────────────────────────────────────────────────────────
    # PB-007  T1548.001 – Privilege Escalation via SUID
    # ──────────────────────────────────────────────────────────────────────────
    {
        "name": "MITRE T1548.001 - Privilege Escalation via SUID",
        "titlePrefix": "[MITRE T1548.001] ",
        "description": (
            "### MITRE ATT&CK T1548.001 – Abuse Elevation Control Mechanism: Setuid and Setgid\n\n"
            "A SUID/SGID binary was modified, created, or executed in an unusual "
            "context, indicating a privilege escalation attempt. The attacker may "
            "be attempting to gain root access.\n\n"
            "**Detection Source:** Wazuh syscheck (file permission change events)\n\n"
            "### Recommended Actions\n"
            "1. Identify the affected SUID binary and the user who modified it.\n"
            "2. Check if a successful root shell was obtained.\n"
            "3. Enrich binary hash via Cortex.\n"
            "4. Remove the SUID bit from the affected binary.\n"
            "5. Audit all SUID binaries on the host."
        ),
        "severity": 3,
        "tlp": 2,
        "pap": 2,
        "tags": ["mitre", "t1548", "t1548.001", "privilege-escalation", "suid", "linux", "agentix"],
        "tasks": [
            {
                "title": "Identify Affected SUID Binary",
                "description": "Extract binary path, old/new permissions, and modifying user from Wazuh syscheck event.",
                "group": "Investigation",
                "order": 0,
            },
            {
                "title": "Check for Successful Root Execution",
                "description": "Query SIEM for root-level commands executed after the SUID modification.",
                "group": "Investigation",
                "order": 1,
            },
            {
                "title": "Enrich Binary Hash via Cortex",
                "description": "Submit the SUID binary hash to VirusTotal to check if it is a known exploit.",
                "group": "Enrichment",
                "order": 2,
            },
            {
                "title": "Remove SUID Bit",
                "description": "Via Wazuh Active Response or manual intervention: chmod u-s <binary>.",
                "group": "Remediation",
                "order": 3,
            },
            {
                "title": "Full SUID Audit",
                "description": "Run: find / -perm /4000 -ls to audit all SUID binaries on the host.",
                "group": "Remediation",
                "order": 4,
            },
            {
                "title": "Isolate if Root Access Confirmed",
                "description": "If investigation confirms root shell was obtained, isolate endpoint via Wazuh.",
                "group": "Containment",
                "order": 5,
            },
        ],
    },
]


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def get_admin_headers(client: httpx.Client) -> dict:
    """Returns admin auth headers. Prefers API key, falls back to session cookie."""
    # Try admin API key first (most reliable)
    if THEHIVE_ADMIN_API_KEY:
        test_headers = {
            "Authorization": f"Bearer {THEHIVE_ADMIN_API_KEY}",
            "Content-Type": "application/json",
        }
        test = client.get(f"{THEHIVE_URL}/api/v1/user/current", headers=test_headers)
        if test.status_code == 200:
            login = test.json().get("login", "?")
            print(f"  ✓ Admin API key valid (user: {login})")
            return test_headers

    # Fallback: session-cookie login
    print(f"  → Trying session login as {THEHIVE_ADMIN_USER}...")
    resp = client.post(
        f"{THEHIVE_URL}/api/login",
        json={"user": THEHIVE_ADMIN_USER, "password": THEHIVE_ADMIN_PASS},
    )
    if resp.status_code != 200:
        print(f"  ✗ Admin login failed: {resp.status_code} – {resp.text}")
        sys.exit(1)

    cookie = resp.headers.get("Set-Cookie", "")
    session_token = ""
    for part in cookie.split(";"):
        part = part.strip()
        if part.startswith("THEHIVE-SESSION="):
            session_token = part
            break

    if not session_token:
        print("  ✗ Could not extract session cookie from admin login.")
        sys.exit(1)

    print("  ✓ Admin session established (cookie auth).")
    return {"Cookie": session_token, "Content-Type": "application/json"}


def create_or_skip_template(client: httpx.Client, admin_headers: dict, template: dict):
    """Creates a case template if it does not already exist."""
    name = template["name"]
    print(f"\n[Template] '{name}'")

    # ── 1. Check if template already exists ──────────────────
    search_resp = client.post(
        f"{THEHIVE_URL}/api/v1/caseTemplate/_search?nparams=0",
        json={"query": [{"_name": "listCaseTemplate"}]},
        headers=admin_headers,
    )
    if search_resp.status_code == 200:
        existing = [t["name"] for t in search_resp.json()]
        if name in existing:
            print("  → Already exists – skipping.")
            return

    # ── 2. Create template ────────────────────────────────────
    create_resp = client.post(
        f"{THEHIVE_URL}/api/v1/caseTemplate",
        json=template,
        headers=admin_headers,
    )
    if create_resp.status_code in (200, 201):
        created_id = create_resp.json().get("_id", "?")
        print(f"  ✓ Created successfully (id={created_id})")
    else:
        print(f"  ✗ Failed: {create_resp.status_code} – {create_resp.text}")


def grant_analyst_template_permission(client: httpx.Client, admin_headers: dict):
    """
    Looks up the 'analyst' profile in organisation 'asdg' and ensures
    it includes the 'manageCaseTemplate' permission by creating/updating
    a custom 'soc-analyst' profile with full SOC permissions.
    """
    print("\n[Profile] Checking permissions for analyst profile in 'asdg'...")

    # List profiles visible to admin
    resp = client.get(f"{THEHIVE_URL}/api/v1/admin/profile", headers=admin_headers)
    if resp.status_code != 200:
        # Fallback – try non-admin route
        resp = client.get(f"{THEHIVE_URL}/api/v1/profile", headers=admin_headers)

    if resp.status_code != 200:
        print(f"  → Cannot list profiles ({resp.status_code}), skipping permission grant.")
        return

    profiles = resp.json() if isinstance(resp.json(), list) else []
    soc_profile_exists = any(p.get("name") == "soc-analyst" for p in profiles)

    soc_permissions = [
        "manageCase/create", "manageCase/update", "manageCase/delete",
        "manageCase/merge", "manageCase/reopen",
        "manageAlert/create", "manageAlert/update", "manageAlert/delete",
        "manageAlert/import", "manageAlert/reopen",
        "manageObservable", "manageTask", "manageComment",
        "manageCaseReport", "manageDashboard", "manageAnalyse",
        "manageProcedure", "managePage", "manageShare",
        "manageAction", "manageKnowledgeBase",
        "manageCustomEvent", "accessTheHiveFS",
        "manageCaseTemplate",           # ← key permission for template creation
    ]

    if not soc_profile_exists:
        print("  → Creating custom 'soc-analyst' profile with manageCaseTemplate...")
        create_resp = client.post(
            f"{THEHIVE_URL}/api/v1/admin/profile",
            json={"name": "soc-analyst", "permissions": soc_permissions},
            headers=admin_headers,
        )
        if create_resp.status_code in (200, 201):
            print("  ✓ 'soc-analyst' profile created.")
        else:
            print(f"  ✗ Could not create profile: {create_resp.status_code} – {create_resp.text}")
    else:
        print("  → 'soc-analyst' profile already exists.")


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────

def main():
    if not THEHIVE_API_KEY:
        print("Error: THEHIVE_API_KEY environment variable is not set.")
        sys.exit(1)

    print("=== TheHive MITRE ATT&CK Setup ===")
    print(f"Target: {THEHIVE_URL}\n")

    with httpx.Client(timeout=15.0) as client:
        # ── Step 1: Verify analyst connectivity ──────────────
        print("[Auth] Verifying analyst API key...")
        analyst_resp = client.get(
            f"{THEHIVE_URL}/api/v1/user/current", headers=ANALYST_API_HEADERS
        )
        if analyst_resp.status_code != 200:
            print(f"  ✗ Analyst authentication failed: {analyst_resp.status_code}")
            sys.exit(1)
        analyst_user = analyst_resp.json().get("login", "?")
        print(f"  ✓ Analyst authenticated: {analyst_user}")

        # ── Step 2: Get admin headers ─────────────────────────
        print("\n[Auth] Obtaining admin credentials...")
        admin_headers = get_admin_headers(client)

        # ── Step 3: Grant permissions (best-effort) ───────────
        grant_analyst_template_permission(client, admin_headers)

        # ── Step 4: Create templates as analyst ─────────────────
        print("\n[Templates] Registering MITRE ATT&CK case templates...")
        for template in TEMPLATES:
            create_or_skip_template(client, ANALYST_API_HEADERS, template)

    print("\n=== Setup Complete ===")
    print("Next steps:")
    print("  1. Run: uv run python scripts/simulate_attack.py --t1003")
    print("  2. Run: uv run python scripts/simulate_attack.py --t1059")


if __name__ == "__main__":
    main()
