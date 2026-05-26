"""
SOC Playbook Definitions
=========================
Defines and registers 7 MITRE ATT&CK playbooks for the Agentix SOC platform.

Playbook List:
  PB-001  T1003.008  Credential Dumping (/etc/shadow)         High
  PB-002  T1059.004  Reverse Shell / C2 Communication         Critical
  PB-003  T1110      Brute Force Login Attack                  Medium
  PB-004  T1550.002  Pass-the-Hash / Lateral Movement         Critical
  PB-005  T1048      Data Exfiltration via DNS Tunneling       High
  PB-006  T1486      Ransomware / Mass Encryption              Critical
  PB-007  T1548.001  Privilege Escalation via SUID Abuse       High

Human Approval Gates:
  Steps that involve destructive or irreversible actions (endpoint isolation,
  user account disable, firewall block) are marked with ApprovalGate and
  require explicit operator confirmation before the SOC agent proceeds.
"""
from soc_mcp.playbooks.base import (
    ApprovalGate,
    Playbook,
    PlaybookStep,
    Severity,
)
from soc_mcp.playbooks.registry import PlaybookRegistry


# ─────────────────────────────────────────────────────────────────────────────
# PB-001  T1003.008 – OS Credential Dumping (/etc/shadow)
# ─────────────────────────────────────────────────────────────────────────────
PB_001 = Playbook(
    id="PB-001",
    name="OS Credential Dumping – /etc/shadow Access",
    description=(
        "Triggered when an unauthorized process reads or copies /etc/shadow. "
        "Indicates active credential harvesting. Immediate containment and "
        "credential rotation required."
    ),
    mitre_ids=["T1003", "T1003.008"],
    severity=Severity.HIGH,
    tags=["credential-dumping", "wazuh-rule-100002", "linux"],
    case_template="MITRE T1003.008 - OS Credential Dumping",
    soar_workflow_id="agentix-mitre-workflow-v1",
    steps=[
        PlaybookStep(
            order=0,
            title="Query SIEM – Identify Offending Process",
            group="Investigation",
            description=(
                "Search Wazuh/Elasticsearch for events matching rule 100002 "
                "on the affected agent. Extract process name, PID, and user context."
            ),
            tool_hint="query_siem_logs",
            parameters={"query": "rule.id:100002 AND agent.id:ctx.agent_id"},
        ),
        PlaybookStep(
            order=1,
            title="Enrich Source IP via Cortex",
            group="Enrichment",
            description=(
                "If a source IP is associated with the event, run VirusTotal "
                "enrichment via Cortex to determine if it is a known C2 or "
                "scanner."
            ),
            tool_hint="get_ip_reputation",
            parameters={"ip_address": "ctx.src_ip"},
            condition="src_ip != ''",
        ),
        PlaybookStep(
            order=2,
            title="Create TheHive Case",
            group="Investigation",
            description=(
                "Open a new TheHive case using the 'MITRE T1003.008' template. "
                "Tag with: mitre, t1003.008, credential-dumping. "
                "Set severity to HIGH (3)."
            ),
            tool_hint="create_case",
            parameters={
                "title": "[T1003.008] Credential Dumping on ctx.agent_name",
                "severity": 3,
                "tags": ["mitre", "t1003.008", "credential-dumping"],
            },
        ),
        PlaybookStep(
            order=3,
            title="Isolate Endpoint via Wazuh Active Response",
            group="Containment",
            description=(
                "Send 'host-deny' active response to the Wazuh agent to cut "
                "network access and prevent lateral movement or exfiltration."
            ),
            tool_hint="isolate_endpoint",
            parameters={"agent_id": "ctx.agent_id"},
            approval_gate=ApprovalGate(
                message=(
                    "⚠️ About to isolate endpoint. "
                    "Agent: ctx.agent_name (ctx.agent_id). "
                    "This will cut all network access. Confirm? [yes/no]"
                ),
                requires_confirmation_for="Wazuh host-deny active response on agent ctx.agent_id",
            ),
        ),
        PlaybookStep(
            order=4,
            title="Rotate Compromised Credentials",
            group="Remediation",
            description=(
                "Immediately reset passwords for all local accounts on the "
                "compromised host. If LDAP/AD is in scope, disable the user account "
                "that initiated the shadow file access."
            ),
            tool_hint="disable_user_account",
            parameters={"username": "ctx.alert.username"},
            approval_gate=ApprovalGate(
                message=(
                    "About to disable user account associated with the incident. "
                    "Username: ctx.alert.username. Confirm? [yes/no]"
                ),
                requires_confirmation_for="Disable IAM/AD user account",
            ),
        ),
        PlaybookStep(
            order=5,
            title="Check for Lateral Movement Indicators",
            group="Investigation",
            description=(
                "Query SIEM for subsequent login attempts, SSH sessions, or "
                "sudo commands from the compromised host within 30 minutes of the "
                "credential dump event."
            ),
            tool_hint="query_siem_logs",
            parameters={"query": "rule.groups:authentication AND agent.id:ctx.agent_id"},
        ),
        PlaybookStep(
            order=6,
            title="Add Case Note – Actions Taken",
            group="Reporting",
            description=(
                "Document all actions taken (isolation, credential rotation, "
                "lateral movement check) in the TheHive case as a timestamped note."
            ),
            tool_hint="add_case_note",
            parameters={
                "case_id": "ctx.case_id",
                "note": "Playbook PB-001 executed. Endpoint isolated. Credentials rotated.",
            },
        ),
        PlaybookStep(
            order=7,
            title="Close or Escalate Case",
            group="Reporting",
            description=(
                "If root cause is confirmed and contained, update TheHive case "
                "status to 'Resolved'. If broader compromise is suspected, escalate "
                "to Tier 2/DFIR team."
            ),
            tool_hint="update_case_status",
            parameters={"case_id": "ctx.case_id", "status": "Resolved"},
        ),
    ],
)


# ─────────────────────────────────────────────────────────────────────────────
# PB-002  T1059.004 – Reverse Shell / C2 Communication
# ─────────────────────────────────────────────────────────────────────────────
PB_002 = Playbook(
    id="PB-002",
    name="Reverse Shell / C2 Communication",
    description=(
        "Detected reverse shell or suspicious bash redirect pattern on a "
        "monitored host. Indicates active attacker presence. Immediate "
        "forensic capture and isolation required."
    ),
    mitre_ids=["T1059", "T1059.004"],
    severity=Severity.CRITICAL,
    tags=["reverse-shell", "c2", "wazuh-rule-100003", "linux"],
    case_template="MITRE T1059.004 - Suspicious Command Execution",
    soar_workflow_id="agentix-mitre-workflow-v1",
    steps=[
        PlaybookStep(
            order=0,
            title="Query SIEM – Capture Event Details",
            group="Investigation",
            description=(
                "Retrieve full event data for rule 100003 on the affected agent. "
                "Note command line, destination IP, and destination port."
            ),
            tool_hint="query_siem_logs",
            parameters={"query": "rule.id:100003 AND agent.id:ctx.agent_id"},
        ),
        PlaybookStep(
            order=1,
            title="Enrich Destination IP (C2 Check)",
            group="Enrichment",
            description=(
                "Run VirusTotal enrichment on the destination IP of the reverse "
                "shell connection to determine if it is a known C2 server."
            ),
            tool_hint="get_ip_reputation",
            parameters={"ip_address": "ctx.src_ip"},
        ),
        PlaybookStep(
            order=2,
            title="Create TheHive Case",
            group="Investigation",
            description=(
                "Open TheHive case using template 'MITRE T1059.004'. "
                "Add observables: destination IP, command line. Severity: CRITICAL (4)."
            ),
            tool_hint="create_case",
            parameters={
                "title": "[T1059.004] Reverse Shell Detected on ctx.agent_name",
                "severity": 4,
                "tags": ["mitre", "t1059.004", "reverse-shell", "c2"],
            },
        ),
        PlaybookStep(
            order=3,
            title="Block C2 Destination IP",
            group="Containment",
            description=(
                "Block the attacker-controlled destination IP on the perimeter "
                "firewall or NAC to cut the active C2 channel."
            ),
            tool_hint="block_ip",
            parameters={"ip_address": "ctx.src_ip"},
            approval_gate=ApprovalGate(
                message=(
                    "About to block IP ctx.src_ip at the firewall. "
                    "This will disrupt any legitimate traffic to this IP. Confirm? [yes/no]"
                ),
                requires_confirmation_for="Firewall block for IP ctx.src_ip",
            ),
        ),
        PlaybookStep(
            order=4,
            title="Isolate Endpoint",
            group="Containment",
            description=(
                "Apply Wazuh host-deny active response to terminate C2 "
                "channel and prevent further commands from executing."
            ),
            tool_hint="isolate_endpoint",
            parameters={"agent_id": "ctx.agent_id"},
            approval_gate=ApprovalGate(
                message=(
                    "About to isolate ctx.agent_name (ctx.agent_id). "
                    "Network access will be cut immediately. Confirm? [yes/no]"
                ),
                requires_confirmation_for="Wazuh host-deny on ctx.agent_id",
            ),
        ),
        PlaybookStep(
            order=5,
            title="Check Persistence Mechanisms",
            group="Investigation",
            description=(
                "Query for cron job modifications, new user accounts, .bashrc "
                "edits, or SUID binaries created around the time of the event."
            ),
            tool_hint="query_siem_logs",
            parameters={
                "query": "(rule.groups:syscheck OR rule.groups:rootcheck) AND agent.id:ctx.agent_id"
            },
        ),
        PlaybookStep(
            order=6,
            title="Trigger Automated SOAR Workflow",
            group="Containment",
            description=(
                "Trigger the Agentix MITRE workflow in the SOAR orchestrator for automated "
                "Cortex enrichment and case task creation."
            ),
            tool_hint="trigger_soar_workflow",
            parameters={
                "workflow_id": "agentix-mitre-workflow-v1",
                "data": {"agent_id": "ctx.agent_id", "src_ip": "ctx.src_ip"},
            },
        ),
        PlaybookStep(
            order=7,
            title="Document and Escalate",
            group="Reporting",
            description=(
                "Add full timeline to TheHive case. If active attacker control "
                "is confirmed, escalate to DFIR team for memory forensics and "
                "full host imaging before remediation."
            ),
            tool_hint="add_case_note",
            parameters={
                "case_id": "ctx.case_id",
                "note": "PB-002 executed. C2 IP blocked. Endpoint isolated. DFIR escalation pending.",
            },
        ),
    ],
)


# ─────────────────────────────────────────────────────────────────────────────
# PB-003  T1110 – Brute Force Login Attack
# ─────────────────────────────────────────────────────────────────────────────
PB_003 = Playbook(
    id="PB-003",
    name="Brute Force Login Attack",
    description=(
        "Multiple failed authentication attempts detected from a single source, "
        "indicating a brute force or password spray attack. Assess whether "
        "any attempt succeeded before containment."
    ),
    mitre_ids=["T1110", "T1110.001", "T1110.003"],
    severity=Severity.MEDIUM,
    tags=["brute-force", "authentication", "linux", "ssh"],
    case_template="MITRE T1110 - Brute Force Attack",
    soar_workflow_id="agentix-brute-force-workflow-v1",
    steps=[
        PlaybookStep(
            order=0,
            title="Query SIEM – Authentication Failures",
            group="Investigation",
            description=(
                "Search for Wazuh rule 5710/5712 (SSH brute force) or "
                "rule 2501/2502 (PAM auth failures). Count failures per source IP "
                "in the last 15 minutes."
            ),
            tool_hint="query_siem_logs",
            parameters={"query": "rule.groups:authentication_failed AND agent.id:ctx.agent_id"},
        ),
        PlaybookStep(
            order=1,
            title="Check for Successful Login After Failures",
            group="Investigation",
            description=(
                "CRITICAL: Query for any successful authentication from the "
                "same source IP within 5 minutes of the last failure. If found, "
                "escalate severity immediately."
            ),
            tool_hint="query_siem_logs",
            parameters={
                "query": "rule.groups:authentication_success AND data.srcip:ctx.src_ip"
            },
        ),
        PlaybookStep(
            order=2,
            title="Enrich Source IP",
            group="Enrichment",
            description=(
                "Check attacker source IP reputation via Cortex VirusTotal "
                "to determine if this is a known scanner, botnet node, or targeted attacker."
            ),
            tool_hint="get_ip_reputation",
            parameters={"ip_address": "ctx.src_ip"},
        ),
        PlaybookStep(
            order=3,
            title="Create TheHive Case",
            group="Investigation",
            description=(
                "Create case using 'MITRE T1110' template. "
                "Include: source IP, targeted account(s), failure count, "
                "whether any login succeeded. Severity: MEDIUM (2) or HIGH (3) if login succeeded."
            ),
            tool_hint="create_case",
            parameters={
                "title": "[T1110] Brute Force Attack from ctx.src_ip",
                "severity": 2,
                "tags": ["mitre", "t1110", "brute-force", "authentication"],
            },
        ),
        PlaybookStep(
            order=4,
            title="Block Source IP at Firewall",
            group="Containment",
            description=(
                "Block the brute-force source IP on the perimeter firewall. "
                "Verify the IP is not a legitimate admin jump host before blocking."
            ),
            tool_hint="block_ip",
            parameters={"ip_address": "ctx.src_ip"},
            approval_gate=ApprovalGate(
                message=(
                    "About to block ctx.src_ip at the firewall. "
                    "Confirm this is not a legitimate admin IP. Proceed? [yes/no]"
                ),
                requires_confirmation_for="Firewall block for brute force source IP ctx.src_ip",
            ),
        ),
        PlaybookStep(
            order=5,
            title="Lock Targeted User Account (if compromised)",
            group="Containment",
            description=(
                "If a successful login was detected, immediately disable the "
                "targeted account via IAM/AD to prevent unauthorized access."
            ),
            tool_hint="disable_user_account",
            parameters={"username": "ctx.alert.target_user"},
            approval_gate=ApprovalGate(
                message=(
                    "A successful login from the attacker IP was detected. "
                    "About to disable account ctx.alert.target_user. Confirm? [yes/no]"
                ),
                requires_confirmation_for="Disable user account ctx.alert.target_user (possible compromise)",
            ),
        ),
        PlaybookStep(
            order=6,
            title="Add Case Notes and Close",
            group="Reporting",
            description=(
                "Document source IP, failure count, success status, and "
                "containment actions in TheHive. Close as 'TruePositive' "
                "or escalate if active session found."
            ),
            tool_hint="add_case_note",
            parameters={
                "case_id": "ctx.case_id",
                "note": "PB-003 executed. Brute force source blocked. Account status reviewed.",
            },
        ),
    ],
)


# ─────────────────────────────────────────────────────────────────────────────
# PB-004  T1550.002 – Pass-the-Hash / Lateral Movement
# ─────────────────────────────────────────────────────────────────────────────
PB_004 = Playbook(
    id="PB-004",
    name="Pass-the-Hash / Lateral Movement",
    description=(
        "NTLM hash reuse or anomalous lateral movement detected between "
        "internal hosts. Attacker may have stolen credentials and is pivoting "
        "through the network. Aggressive containment required."
    ),
    mitre_ids=["T1550", "T1550.002"],
    severity=Severity.CRITICAL,
    tags=["pass-the-hash", "lateral-movement", "ntlm", "windows"],
    case_template="MITRE T1550.002 - Pass-the-Hash / Lateral Movement",
    soar_workflow_id=None,
    steps=[
        PlaybookStep(
            order=0,
            title="Query SIEM – Detect NTLM Auth Anomalies",
            group="Investigation",
            description=(
                "Search for Wazuh rules indicating NTLM relay or pass-the-hash "
                "(rules 60106, 60107 or custom). Identify source and destination hosts."
            ),
            tool_hint="query_siem_logs",
            parameters={"query": "rule.groups:windows AND data.win.system.eventID:4624 AND data.win.eventdata.logonType:3"},
        ),
        PlaybookStep(
            order=1,
            title="Map Lateral Movement Path",
            group="Investigation",
            description=(
                "Trace the authentication chain: identify which account was used, "
                "from which source host, to which destination. Visualize in TheHive "
                "using graph observables."
            ),
            tool_hint="query_siem_logs",
            parameters={"query": "data.win.system.eventID:(4624 OR 4625 OR 4648) AND data.win.eventdata.subjectUserName:ctx.alert.username"},
        ),
        PlaybookStep(
            order=2,
            title="Get Wazuh Agent Info for All Affected Hosts",
            group="Investigation",
            description=(
                "Retrieve Wazuh agent details for all hosts in the lateral "
                "movement chain to get their OS, IP, and last seen times."
            ),
            tool_hint="get_endpoint_info",
            parameters={"agent_id": "ctx.agent_id"},
        ),
        PlaybookStep(
            order=3,
            title="Create High-Severity TheHive Case",
            group="Investigation",
            description=(
                "Open case using 'MITRE T1550.002' template. "
                "Include all affected hosts as observables. Severity: CRITICAL (4)."
            ),
            tool_hint="create_case",
            parameters={
                "title": "[T1550.002] Pass-the-Hash Lateral Movement – ctx.agent_name",
                "severity": 4,
                "tags": ["mitre", "t1550.002", "pass-the-hash", "lateral-movement"],
            },
        ),
        PlaybookStep(
            order=4,
            title="Isolate Source Host",
            group="Containment",
            description=(
                "Isolate the originating host to stop lateral movement. "
                "This is the host where pass-the-hash was initiated."
            ),
            tool_hint="isolate_endpoint",
            parameters={"agent_id": "ctx.agent_id"},
            approval_gate=ApprovalGate(
                message=(
                    "About to isolate ctx.agent_name (ctx.agent_id) — the source "
                    "of lateral movement. This will cut ALL network access. "
                    "Confirm isolation? [yes/no]"
                ),
                requires_confirmation_for="Wazuh host-deny on lateral movement source ctx.agent_id",
            ),
        ),
        PlaybookStep(
            order=5,
            title="Force NTLM Hash Reset for Affected Account",
            group="Remediation",
            description=(
                "Disable the compromised account and force a password reset "
                "to invalidate stolen NTLM hashes. Coordinate with AD team."
            ),
            tool_hint="disable_user_account",
            parameters={"username": "ctx.alert.username"},
            approval_gate=ApprovalGate(
                message=(
                    "About to disable account ctx.alert.username to invalidate "
                    "stolen NTLM hash. This may impact active sessions. Confirm? [yes/no]"
                ),
                requires_confirmation_for="Disable AD account and force password reset",
            ),
        ),
        PlaybookStep(
            order=6,
            title="Escalate to DFIR",
            group="Reporting",
            description=(
                "Pass-the-Hash indicates credential compromise at scale. "
                "Escalate immediately to DFIR for memory forensics, "
                "NTDS.dit assessment, and Kerberoasting sweep."
            ),
            tool_hint="add_case_note",
            parameters={
                "case_id": "ctx.case_id",
                "note": "PB-004 executed. DFIR escalation required for full credential audit.",
            },
        ),
    ],
)


# ─────────────────────────────────────────────────────────────────────────────
# PB-005  T1048 – Data Exfiltration via DNS Tunneling
# ─────────────────────────────────────────────────────────────────────────────
PB_005 = Playbook(
    id="PB-005",
    name="Data Exfiltration via DNS Tunneling",
    description=(
        "Anomalous DNS query volume or long/encoded DNS queries detected, "
        "indicating possible data exfiltration via DNS tunneling (e.g. iodine, dnscat2). "
        "Identify scope of data loss and block channel."
    ),
    mitre_ids=["T1048", "T1048.003"],
    severity=Severity.HIGH,
    tags=["exfiltration", "dns-tunneling", "covert-channel"],
    case_template="MITRE T1048 - Data Exfiltration via DNS",
    soar_workflow_id=None,
    steps=[
        PlaybookStep(
            order=0,
            title="Query SIEM – Detect DNS Anomalies",
            group="Investigation",
            description=(
                "Search for Wazuh alerts on high DNS query rate or long DNS "
                "subdomains (rule groups: network). Look for queries >50 chars "
                "or >100 queries/min from a single host."
            ),
            tool_hint="query_siem_logs",
            parameters={"query": "rule.groups:network_traffic AND data.dns.type:query AND agent.id:ctx.agent_id"},
        ),
        PlaybookStep(
            order=1,
            title="Enrich DNS Destination Domain",
            group="Enrichment",
            description=(
                "Run VirusTotal/PassiveDNS enrichment on the suspicious DNS "
                "destination domain to check if it is a known C2 or DGA domain."
            ),
            tool_hint="get_domain_url_reputation",
            parameters={"url_or_domain": "ctx.alert.dns_domain"},
        ),
        PlaybookStep(
            order=2,
            title="Estimate Exfiltration Volume",
            group="Investigation",
            description=(
                "Calculate total DNS query payload size over the detection window "
                "to estimate data volume exfiltrated. Document in case."
            ),
            tool_hint="query_siem_logs",
            parameters={"query": "data.dns.type:query AND data.dns.qname:ctx.alert.dns_domain"},
        ),
        PlaybookStep(
            order=3,
            title="Create TheHive Case",
            group="Investigation",
            description=(
                "Open case using 'MITRE T1048' template. "
                "Add DNS domain as observable. Severity: HIGH (3)."
            ),
            tool_hint="create_case",
            parameters={
                "title": "[T1048] DNS Exfiltration Detected from ctx.agent_name",
                "severity": 3,
                "tags": ["mitre", "t1048", "dns-tunneling", "exfiltration"],
            },
        ),
        PlaybookStep(
            order=4,
            title="Block DNS Tunnel Destination",
            group="Containment",
            description=(
                "Block the destination IP of the DNS tunnel at the firewall "
                "and/or add the domain to DNS sinkhole. "
                "Coordinate with network team."
            ),
            tool_hint="block_ip",
            parameters={"ip_address": "ctx.src_ip"},
            approval_gate=ApprovalGate(
                message=(
                    "About to block DNS tunnel destination ctx.src_ip. "
                    "Confirm this will not affect legitimate DNS traffic? [yes/no]"
                ),
                requires_confirmation_for="Firewall block for DNS exfiltration destination IP",
            ),
        ),
        PlaybookStep(
            order=5,
            title="Notify Data Owner / DPO",
            group="Reporting",
            description=(
                "If exfiltration of PII or sensitive data is confirmed, "
                "notify the Data Protection Officer and initiate breach assessment "
                "per GDPR/regulatory requirements."
            ),
            tool_hint="add_case_note",
            parameters={
                "case_id": "ctx.case_id",
                "note": "PB-005: DNS tunnel blocked. DPO notification required if sensitive data confirmed.",
            },
        ),
    ],
)


# ─────────────────────────────────────────────────────────────────────────────
# PB-006  T1486 – Ransomware / Mass Encryption
# ─────────────────────────────────────────────────────────────────────────────
PB_006 = Playbook(
    id="PB-006",
    name="Ransomware / Mass File Encryption",
    description=(
        "Detected mass file modification, rename events, or ransom note creation. "
        "Indicates active ransomware execution. This is a P0 incident. "
        "IMMEDIATE isolation and escalation required — do NOT wait for enrichment."
    ),
    mitre_ids=["T1486"],
    severity=Severity.CRITICAL,
    tags=["ransomware", "encryption", "p0-incident", "wazuh-syscheck"],
    case_template="MITRE T1486 - Ransomware / Data Encrypted for Impact",
    soar_workflow_id="agentix-ransomware-workflow-v1",
    steps=[
        PlaybookStep(
            order=0,
            title="⚡ IMMEDIATE: Isolate Affected Host",
            group="Containment",
            description=(
                "DO NOT WAIT for investigation. Immediately isolate the affected "
                "host via Wazuh Active Response to stop encryption spread. "
                "Time is critical."
            ),
            tool_hint="isolate_endpoint",
            parameters={"agent_id": "ctx.agent_id"},
            approval_gate=ApprovalGate(
                message=(
                    "🚨 RANSOMWARE DETECTED on ctx.agent_name (ctx.agent_id). "
                    "Immediate isolation required to prevent spread. "
                    "Confirm emergency isolation NOW? [yes/no]"
                ),
                requires_confirmation_for="EMERGENCY Wazuh host-deny for ransomware containment",
            ),
        ),
        PlaybookStep(
            order=1,
            title="Query SIEM – Scope of Mass File Changes",
            group="Investigation",
            description=(
                "Search Wazuh syscheck events for the past 30 minutes to count "
                "total file modification/deletion events. Identify encrypted file "
                "extensions and ransom note filenames."
            ),
            tool_hint="query_siem_logs",
            parameters={"query": "rule.groups:syscheck AND agent.id:ctx.agent_id AND rule.level:>=10"},
        ),
        PlaybookStep(
            order=2,
            title="Identify Ransomware Process",
            group="Investigation",
            description=(
                "Look for the process responsible for file changes. "
                "Check for known ransomware process names, unsigned executables, "
                "or processes running from temp/user-writable paths."
            ),
            tool_hint="query_siem_logs",
            parameters={"query": "data.win.system.eventID:(4688 OR 1) AND agent.id:ctx.agent_id"},
        ),
        PlaybookStep(
            order=3,
            title="Enrich Ransomware File Hash",
            group="Enrichment",
            description=(
                "If ransomware binary hash is available from the syscheck event, "
                "submit to Cortex VirusTotal to identify the ransomware family."
            ),
            tool_hint="get_file_reputation",
            parameters={"file_hash": "ctx.alert.file_hash"},
            condition="alert.file_hash != ''",
        ),
        PlaybookStep(
            order=4,
            title="Create P0 TheHive Case",
            group="Investigation",
            description=(
                "Open critical-severity case using 'MITRE T1486' template. "
                "Add: ransom note content, encrypted extension, ransomware family "
                "(if known). Severity: CRITICAL (4). Assign to on-call analyst."
            ),
            tool_hint="create_case",
            parameters={
                "title": "🚨 [T1486] RANSOMWARE ACTIVE – ctx.agent_name",
                "severity": 4,
                "tags": ["mitre", "t1486", "ransomware", "p0", "active-incident"],
            },
        ),
        PlaybookStep(
            order=5,
            title="Block Ransomware C2 (if identified)",
            group="Containment",
            description=(
                "If a C2 IP/domain was identified from the ransomware binary or "
                "network logs, block it immediately at the firewall to prevent "
                "key transmission to attacker."
            ),
            tool_hint="block_ip",
            parameters={"ip_address": "ctx.src_ip"},
            approval_gate=ApprovalGate(
                message=(
                    "About to block ransomware C2 IP ctx.src_ip. Confirm? [yes/no]"
                ),
                requires_confirmation_for="Block ransomware C2 IP at perimeter firewall",
            ),
        ),
        PlaybookStep(
            order=6,
            title="Trigger Automated SOAR Ransomware Workflow",
            group="Containment",
            description=(
                "Trigger the automated SOAR ransomware workflow to "
                "coordinate Wazuh isolation, Cortex family identification, "
                "and TheHive task assignment across the team."
            ),
            tool_hint="trigger_soar_workflow",
            parameters={
                "workflow_id": "agentix-ransomware-workflow-v1",
                "data": {"agent_id": "ctx.agent_id", "case_id": "ctx.case_id"},
            },
        ),
        PlaybookStep(
            order=7,
            title="Initiate Backup Restore Assessment",
            group="Remediation",
            description=(
                "Contact backup/DR team to assess: last clean backup date, "
                "restore time objective, and whether backups are also encrypted. "
                "Document in TheHive case."
            ),
            tool_hint="add_case_note",
            parameters={
                "case_id": "ctx.case_id",
                "note": "PB-006: Host isolated. Backup team notified. Family identification pending.",
            },
        ),
    ],
)


# ─────────────────────────────────────────────────────────────────────────────
# PB-007  T1548.001 – Privilege Escalation via SUID Abuse
# ─────────────────────────────────────────────────────────────────────────────
PB_007 = Playbook(
    id="PB-007",
    name="Privilege Escalation – SUID/SGID Abuse",
    description=(
        "A SUID/SGID binary was modified, created, or executed in an unusual "
        "context, indicating potential privilege escalation attempt. "
        "Attacker may be attempting to gain root."
    ),
    mitre_ids=["T1548", "T1548.001"],
    severity=Severity.HIGH,
    tags=["privilege-escalation", "suid", "linux", "wazuh-syscheck"],
    case_template="MITRE T1548.001 - Privilege Escalation via SUID",
    soar_workflow_id=None,
    steps=[
        PlaybookStep(
            order=0,
            title="Query SIEM – SUID Event Details",
            group="Investigation",
            description=(
                "Search Wazuh syscheck for recently modified or new SUID binaries. "
                "Check rule groups: syscheck, rootcheck. Note file path, "
                "old vs new permissions, and user who made the change."
            ),
            tool_hint="query_siem_logs",
            parameters={"query": "rule.groups:syscheck AND data.syscheck.mode:realtime AND agent.id:ctx.agent_id"},
        ),
        PlaybookStep(
            order=1,
            title="Check for Successful Root Command Execution",
            group="Investigation",
            description=(
                "Search for subsequent root-level commands executed after the "
                "SUID modification. Check for sudo, su, or direct root shell access."
            ),
            tool_hint="query_siem_logs",
            parameters={"query": "data.dstuser:root AND agent.id:ctx.agent_id AND rule.level:>=10"},
        ),
        PlaybookStep(
            order=2,
            title="Get User Account Info",
            group="Investigation",
            description=(
                "Retrieve information on the user account that modified the SUID "
                "binary to determine if this is a service account or human user."
            ),
            tool_hint="get_ad_user_info",
            parameters={"username": "ctx.alert.username"},
        ),
        PlaybookStep(
            order=3,
            title="Enrich File Hash via Cortex",
            group="Enrichment",
            description=(
                "If the SUID binary has a known hash (from syscheck), submit it "
                "to Cortex VirusTotal to determine if it is a known exploit binary."
            ),
            tool_hint="get_file_reputation",
            parameters={"file_hash": "ctx.alert.file_hash"},
            condition="alert.file_hash != ''",
        ),
        PlaybookStep(
            order=4,
            title="Create TheHive Case",
            group="Investigation",
            description=(
                "Open case using 'MITRE T1548.001' template. "
                "Include: affected binary path, old/new permissions, user. "
                "Severity: HIGH (3)."
            ),
            tool_hint="create_case",
            parameters={
                "title": "[T1548.001] SUID Escalation Attempt on ctx.agent_name",
                "severity": 3,
                "tags": ["mitre", "t1548.001", "privilege-escalation", "suid"],
            },
        ),
        PlaybookStep(
            order=5,
            title="Isolate Endpoint if Root Shell Confirmed",
            group="Containment",
            description=(
                "If investigation confirms a successful root shell was obtained, "
                "isolate the endpoint immediately. Otherwise, remove SUID bit "
                "manually and monitor."
            ),
            tool_hint="isolate_endpoint",
            parameters={"agent_id": "ctx.agent_id"},
            approval_gate=ApprovalGate(
                message=(
                    "Root-level access appears to have been gained on ctx.agent_name. "
                    "Confirm endpoint isolation to prevent further damage? [yes/no]"
                ),
                requires_confirmation_for="Wazuh host-deny after confirmed root escalation",
            ),
        ),
        PlaybookStep(
            order=6,
            title="Remove SUID Bit and Audit All SUID Binaries",
            group="Remediation",
            description=(
                "Via Wazuh Active Response or manual intervention: "
                "chmod u-s on the affected binary. Run 'find / -perm /4000' "
                "to audit all SUID binaries on the host."
            ),
            tool_hint="add_case_note",
            parameters={
                "case_id": "ctx.case_id",
                "note": "PB-007: SUID binary identified. Manual chmod u-s required. Full SUID audit initiated.",
            },
        ),
        PlaybookStep(
            order=7,
            title="Document and Close",
            group="Reporting",
            description=(
                "Document: affected binary, user, root access achieved (yes/no), "
                "remediation steps taken. Update TheHive case status."
            ),
            tool_hint="update_case_status",
            parameters={"case_id": "ctx.case_id", "status": "Resolved"},
        ),
    ],
)


# ─────────────────────────────────────────────────────────────────────────────
# Register All Playbooks
# ─────────────────────────────────────────────────────────────────────────────
_registry = PlaybookRegistry.instance()
_registry.register_many(PB_001, PB_002, PB_003, PB_004, PB_005, PB_006, PB_007)
