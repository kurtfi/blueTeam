/**
 * Agentix Web UI Core JavaScript Logic
 * Implements Obsidian Sentinel design system client.
 */

// Application State
let activeSessionId = null;
let activeAgent = 'soc_analyst';
let isStreaming = false;
const activeSessionsList = new Set();

// DOM Elements
const loginContainer = document.getElementById('login-container');
const appContainer = document.getElementById('app-container');
const loginForm = document.getElementById('login-form');
const loginError = document.getElementById('login-error');
const errorText = document.getElementById('error-text');

const chatInput = document.getElementById('detail-chat-input');
const chatMessagesContainer = document.getElementById('detail-timeline');
const terminalInputForm = document.getElementById('detail-chat-form');
const thinkingIndicator = document.getElementById('thinking-indicator');
const sessionSelect = document.getElementById('session-select');
const newSessionBtn = document.getElementById('new-session-btn');
const logoutBtn = document.getElementById('logout-btn');

const profileUsername = document.getElementById('profile-username');
const profileRole = document.getElementById('profile-role');

// Views/Tab Switching Elements
const navItems = {
    dashboard: document.getElementById('nav-dashboard'),
    sessions: document.getElementById('nav-sessions'),
    hitl: document.getElementById('nav-hitl'),
    personas: document.getElementById('nav-personas'),
    playbooks: document.getElementById('nav-playbooks'),
    settings: document.getElementById('nav-settings')
};

const panels = {
    dashboard: document.getElementById('panel-dashboard'),
    sessions: document.getElementById('panel-sessions'),
    hitl: document.getElementById('panel-hitl'),
    'session-detail': document.getElementById('panel-session-detail'),
    personas: document.getElementById('panel-personas'),
    playbooks: document.getElementById('panel-playbooks'),
    settings: document.getElementById('panel-settings')
};

const viewTitle = document.getElementById('view-title');
const viewDesc = document.getElementById('view-desc');
const sessionControls = document.getElementById('session-controls');

// Dashboard Stats Elements
const statActive = document.getElementById('stat-active');
const statHitl = document.getElementById('stat-hitl');
const statToday = document.getElementById('stat-today');
const statCompleted = document.getElementById('stat-completed');
const dashboardRecentList = document.getElementById('dashboard-recent-list');
const verdictTpCount = document.getElementById('verdict-tp-count');
const verdictFpCount = document.getElementById('verdict-fp-count');
const verdictUndCount = document.getElementById('verdict-und-count');
const statAvgDuration = document.getElementById('stat-avg-duration');
const dashboardRefreshBtn = document.getElementById('dashboard-refresh-btn');

// Missing Global Declarations
const agentsCardsContainer = document.getElementById('agents-cards-container');
const playbooksListContainer = document.getElementById('playbooks-list-container');
const playbooksMarkdownViewer = document.getElementById('playbooks-markdown-viewer');
const settingsForm = document.getElementById('settings-form');
const settingsSavedToast = document.getElementById('settings-saved-toast');

// Sessions List Elements
const sessionsListContainer = document.getElementById('sessions-list-container');
const sessionsSearch = document.getElementById('sessions-search');
const filterSource = document.getElementById('filter-source');
const filterStatus = document.getElementById('filter-status');
const sessionsRefreshBtn = document.getElementById('sessions-refresh-btn');

// HITL Queue Elements
const hitlListContainer = document.getElementById('hitl-list-container');
const hitlRefreshBtn = document.getElementById('hitl-refresh-btn');
const hitlBadgeCount = document.getElementById('hitl-badge-count');

// Session Detail Elements
const detailDisplayName = document.getElementById('detail-display-name');
const detailSourceBadge = document.getElementById('detail-source-badge');
const detailStatusBadge = document.getElementById('detail-status-badge');
const detailVerdictBadge = document.getElementById('detail-verdict-badge');
const detailTimeBadge = document.getElementById('detail-time-badge');
const detailBackBtn = document.getElementById('detail-back-btn');
const detailWazuhCard = document.getElementById('detail-wazuh-card');
const detailRawAlertCard = document.getElementById('detail-raw-alert-card');
const detailHitlCard = document.getElementById('detail-hitl-card');
const detailWorkspaceCard = document.getElementById('detail-workspace-card');
const detailChatInputCard = document.getElementById('detail-chat-input-card');
const detailChatForm = document.getElementById('detail-chat-form');

const wazuhRuleId = document.getElementById('wazuh-rule-id');
const wazuhRuleLevel = document.getElementById('wazuh-rule-level');
const wazuhSrcIp = document.getElementById('wazuh-src-ip');
const wazuhMitreIds = document.getElementById('wazuh-mitre-ids');
const wazuhRawPayload = document.getElementById('wazuh-raw-payload');

const detailHitlTool = document.getElementById('detail-hitl-tool');
const detailHitlArgs = document.getElementById('detail-hitl-args');
const detailHitlApprove = document.getElementById('detail-hitl-approve');
const detailHitlReject = document.getElementById('detail-hitl-reject');

const detailWorkspaceFiles = document.getElementById('detail-workspace-files');
const rawAlertToggleHeader = document.getElementById('raw-alert-toggle-header');

// Playbook details catalog
const PLAYBOOK_CATALOG = {
    "PB-001": {
        id: "PB-001",
        name: "OS Credential Dumping – /etc/shadow Access",
        severity: "HIGH",
        mitre_ids: ["T1003", "T1003.008"],
        description: "Triggered when an unauthorized process reads or copies /etc/shadow. Indicates active credential harvesting. Immediate containment and credential rotation required.",
        steps: [
            { order: 0, title: "Query SIEM – Identify Offending Process", group: "Investigation", tool: "query_siem_logs", desc: "Search Wazuh/Elasticsearch for events matching rule 100002 on the affected agent. Extract process name, PID, and user context." },
            { order: 1, title: "Enrich Source IP via Cortex", group: "Enrichment", tool: "get_ip_reputation", desc: "If a source IP is associated with the event, run VirusTotal enrichment via Cortex to determine if it is a known C2 or scanner." },
            { order: 2, title: "Create TheHive Case", group: "Investigation", tool: "create_case", desc: "Open a new TheHive case using the 'MITRE T1003.008' template. Tag with: mitre, t1003.008, credential-dumping. Set severity to HIGH (3)." },
            { order: 3, title: "Isolate Endpoint via Wazuh Active Response", group: "Containment", tool: "isolate_endpoint", desc: "Send 'host-deny' active response to the Wazuh agent to cut network access and prevent lateral movement or exfiltration.", approval: "Wazuh host-deny active response on agent" },
            { order: 4, title: "Rotate Compromised Credentials", group: "Remediation", tool: "disable_user_account", desc: "Immediately reset passwords for all local accounts on the compromised host. If LDAP/AD is in scope, disable the user account that initiated the shadow file access.", approval: "Disable IAM/AD user account" },
            { order: 5, title: "Check for Lateral Movement Indicators", group: "Investigation", tool: "query_siem_logs", desc: "Query SIEM for subsequent login attempts, SSH sessions, or sudo commands from the compromised host within 30 minutes of the credential dump event." },
            { order: 6, title: "Add Case Note – Actions Taken", group: "Reporting", tool: "add_case_note", desc: "Document all actions taken (isolation, credential rotation, lateral movement check) in the TheHive case as a timestamped note." },
            { order: 7, title: "Close or Escalate Case", group: "Reporting", tool: "update_case_status", desc: "If root cause is confirmed and contained, update TheHive case status to 'Resolved'. If broader compromise is suspected, escalate to Tier 2/DFIR team." }
        ]
    },
    "PB-002": {
        id: "PB-002",
        name: "Reverse Shell / C2 Communication",
        severity: "CRITICAL",
        mitre_ids: ["T1059", "T1059.004"],
        description: "Detected reverse shell or suspicious bash redirect pattern on a monitored host. Indicates active attacker presence. Immediate forensic capture and isolation required.",
        steps: [
            { order: 0, title: "Query SIEM – Capture Event Details", group: "Investigation", tool: "query_siem_logs", desc: "Retrieve full event data for rule 100003 on the affected agent. Note command line, destination IP, and destination port." },
            { order: 1, title: "Enrich Destination IP (C2 Check)", group: "Enrichment", tool: "get_ip_reputation", desc: "Run VirusTotal enrichment on the destination IP of the reverse shell connection to determine if it is a known C2 server." },
            { order: 2, title: "Create TheHive Case", group: "Investigation", tool: "create_case", desc: "Open TheHive case using template 'MITRE T1059.004'. Add observables: destination IP, command line. Severity: CRITICAL (4)." },
            { order: 3, title: "Block C2 Destination IP", group: "Containment", tool: "block_ip", desc: "Block the attacker-controlled destination IP on the perimeter firewall or NAC to cut the active C2 channel.", approval: "Firewall block for IP" },
            { order: 4, title: "Isolate Endpoint", group: "Containment", tool: "isolate_endpoint", desc: "Apply Wazuh host-deny active response to terminate C2 channel and prevent further commands from executing.", approval: "Wazuh host-deny on agent" },
            { order: 5, title: "Check Persistence Mechanisms", group: "Investigation", tool: "query_siem_logs", desc: "Query for cron job modifications, new user accounts, .bashrc edits, or SUID binaries created around the time of the event." },
            { order: 6, title: "Trigger Automated SOAR Workflow", group: "Containment", tool: "trigger_soar_workflow", desc: "Trigger the Agentix MITRE workflow in the SOAR orchestrator for automated Cortex enrichment and case task creation." },
            { order: 7, title: "Document and Escalate", group: "Reporting", tool: "add_case_note", desc: "Add full timeline to TheHive case. If active attacker control is confirmed, escalate to DFIR team for memory forensics and full host imaging before remediation." }
        ]
    },
    "PB-003": {
        id: "PB-003",
        name: "Brute Force Login Attack",
        severity: "MEDIUM",
        mitre_ids: ["T1110", "T1110.001", "T1110.003"],
        description: "Multiple failed authentication attempts detected from a single source, indicating a brute force or password spray attack. Assess whether any attempt succeeded before containment.",
        steps: [
            { order: 0, title: "Query SIEM – Authentication Failures", group: "Investigation", tool: "query_siem_logs", desc: "Search for Wazuh rule 5710/5712 (SSH brute force) or rule 2501/2502 (PAM auth failures). Count failures per source IP in the last 15 minutes." },
            { order: 1, title: "Check for Successful Login After Failures", group: "Investigation", tool: "query_siem_logs", desc: "CRITICAL: Query for any successful authentication from the same source IP within 5 minutes of the last failure. If found, escalate severity immediately." },
            { order: 2, title: "Enrich Source IP", group: "Enrichment", tool: "get_ip_reputation", desc: "Check attacker source IP reputation via Cortex VirusTotal to determine if this is a known scanner, botnet node, or targeted attacker." },
            { order: 3, title: "Create TheHive Case", group: "Investigation", tool: "create_case", desc: "Create case using 'MITRE T1110' template. Include: source IP, targeted account(s), failure count, whether any login succeeded. Severity: MEDIUM (2) or HIGH (3) if login succeeded." },
            { order: 4, title: "Block Source IP at Firewall", group: "Containment", tool: "block_ip", desc: "Block the brute-force source IP on the perimeter firewall. Verify the IP is not a legitimate admin jump host before blocking.", approval: "Firewall block for brute force source IP" },
            { order: 5, title: "Lock Targeted User Account", group: "Containment", tool: "disable_user_account", desc: "If a successful login was detected, immediately disable the targeted account via IAM/AD to prevent unauthorized access.", approval: "Disable user account (possible compromise)" },
            { order: 6, title: "Add Case Notes and Close", group: "Reporting", tool: "add_case_note", desc: "Document source IP, failure count, success status, and containment actions in TheHive. Close as 'TruePositive' or escalate if active session found." }
        ]
    },
    "PB-004": {
        id: "PB-004",
        name: "Pass-the-Hash / Lateral Movement",
        severity: "CRITICAL",
        mitre_ids: ["T1550", "T1550.002"],
        description: "NTLM hash reuse or anomalous lateral movement detected between internal hosts. Attacker may have stolen credentials and is pivoting through the network. Aggressive containment required.",
        steps: [
            { order: 0, title: "Query SIEM – Detect NTLM Auth Anomalies", group: "Investigation", tool: "query_siem_logs", desc: "Search for Wazuh rules indicating NTLM relay or pass-the-hash (rules 60106, 60107 or custom). Identify source and destination hosts." },
            { order: 1, title: "Map Lateral Movement Path", group: "Investigation", tool: "query_siem_logs", desc: "Trace the authentication chain: identify which account was used, from which source host, to which destination." },
            { order: 2, title: "Get Wazuh Agent Info for All Affected Hosts", group: "Investigation", tool: "get_endpoint_info", desc: "Retrieve Wazuh agent details for all hosts in the lateral movement chain to get their OS, IP, and last seen times." },
            { order: 3, title: "Create High-Severity TheHive Case", group: "Investigation", tool: "create_case", desc: "Open case using 'MITRE T1550.002' template. Include all affected hosts as observables. Severity: CRITICAL (4)." },
            { order: 4, title: "Isolate Source Host", group: "Containment", tool: "isolate_endpoint", desc: "Isolate the originating host to stop lateral movement. This is the host where pass-the-hash was initiated.", approval: "Wazuh host-deny on lateral movement source" },
            { order: 5, title: "Force NTLM Hash Reset for Affected Account", group: "Remediation", tool: "disable_user_account", desc: "Disable the compromised account and force a password reset to invalidate stolen NTLM hashes. Coordinate with AD team.", approval: "Disable AD account and force password reset" },
            { order: 6, title: "Escalate to DFIR", group: "Reporting", tool: "add_case_note", desc: "Pass-the-Hash indicates credential compromise at scale. Escalate immediately to DFIR for memory forensics, NTDS.dit assessment, and Kerberoasting sweep." }
        ]
    },
    "PB-005": {
        id: "PB-005",
        name: "Data Exfiltration via DNS Tunneling",
        severity: "HIGH",
        mitre_ids: ["T1048", "T1048.003"],
        description: "Anomalous DNS query volume or long/encoded DNS queries detected, indicating possible data exfiltration via DNS tunneling (e.g. iodine, dnscat2). Identify scope of data loss and block channel.",
        steps: [
            { order: 0, title: "Query SIEM – Detect DNS Anomalies", group: "Investigation", tool: "query_siem_logs", desc: "Search for Wazuh alerts on high DNS query rate or long DNS subdomains. Look for queries >50 chars or >100 queries/min from a single host." },
            { order: 1, title: "Enrich DNS Destination Domain", group: "Enrichment", tool: "get_domain_url_reputation", desc: "Run VirusTotal/PassiveDNS enrichment on the suspicious DNS destination domain to check if it is a known C2 or DGA domain." },
            { order: 2, title: "Estimate Exfiltration Volume", group: "Investigation", tool: "query_siem_logs", desc: "Calculate total DNS query payload size over the detection window to estimate data volume exfiltrated. Document in case." },
            { order: 3, title: "Create TheHive Case", group: "Investigation", tool: "create_case", desc: "Open case using 'MITRE T1048' template. Add DNS domain as observable. Severity: HIGH (3)." },
            { order: 4, title: "Block DNS Tunnel Destination", group: "Containment", tool: "block_ip", desc: "Block the destination IP of the DNS tunnel at the firewall and/or add the domain to DNS sinkhole.", approval: "Firewall block for DNS exfiltration destination IP" },
            { order: 5, title: "Notify Data Owner / DPO", group: "Reporting", tool: "add_case_note", desc: "If exfiltration of PII or sensitive data is confirmed, notify the Data Protection Officer and initiate breach assessment." }
        ]
    },
    "PB-006": {
        id: "PB-006",
        name: "Ransomware / Mass File Encryption",
        severity: "CRITICAL",
        mitre_ids: ["T1486"],
        description: "Detected mass file modification, rename events, or ransom note creation. Indicates active ransomware execution. This is a P0 incident. IMMEDIATE isolation and escalation required — do NOT wait for enrichment.",
        steps: [
            { order: 0, title: "⚡ IMMEDIATE: Isolate Affected Host", group: "Containment", tool: "isolate_endpoint", desc: "DO NOT WAIT for investigation. Immediately isolate the affected host via Wazuh Active Response to stop encryption spread.", approval: "EMERGENCY Wazuh host-deny for ransomware containment" },
            { order: 1, title: "Query SIEM – Scope of Mass File Changes", group: "Investigation", tool: "query_siem_logs", desc: "Search Wazuh syscheck events for the past 30 minutes to count total file modification/deletion events. Identify encrypted file extensions and ransom note filenames." },
            { order: 2, title: "Identify Ransomware Process", group: "Investigation", tool: "query_siem_logs", desc: "Look for the process responsible for file changes. Check for known ransomware process names, unsigned executables, or processes running from temp/user-writable paths." },
            { order: 3, title: "Enrich Ransomware File Hash", group: "Enrichment", tool: "get_file_reputation", desc: "If ransomware binary hash is available from the syscheck event, submit to Cortex VirusTotal to identify the ransomware family." },
            { order: 4, title: "Create P0 TheHive Case", group: "Investigation", tool: "create_case", desc: "Open critical-severity case using 'MITRE T1486' template. Add: ransom note content, encrypted extension, ransomware family. Severity: CRITICAL (4)." },
            { order: 5, title: "Block Ransomware C2", group: "Containment", tool: "block_ip", desc: "If a C2 IP/domain was identified from the ransomware binary or network logs, block it immediately at the firewall to prevent key transmission.", approval: "Block ransomware C2 IP at perimeter firewall" },
            { order: 6, title: "Trigger Automated SOAR Ransomware Workflow", group: "Containment", tool: "trigger_soar_workflow", desc: "Trigger the automated SOAR ransomware workflow to coordinate Wazuh isolation, Cortex family identification, and TheHive task assignment." },
            { order: 7, title: "Initiate Backup Restore Assessment", group: "Remediation", tool: "add_case_note", desc: "Contact backup/DR team to assess: last clean backup date, restore time objective, and whether backups are also encrypted." }
        ]
    },
    "PB-007": {
        id: "PB-007",
        name: "Privilege Escalation – SUID/SGID Abuse",
        severity: "HIGH",
        mitre_ids: ["T1548", "T1548.001"],
        description: "A SUID/SGID binary was modified, created, or executed in an unusual context, indicating potential privilege escalation attempt. Attacker may be attempting to gain root.",
        steps: [
            { order: 0, title: "Query SIEM – SUID Event Details", group: "Investigation", tool: "query_siem_logs", desc: "Search Wazuh syscheck for recently modified or new SUID binaries. Check rule groups: syscheck, rootcheck. Note file path, old vs new permissions, and user who made the change." },
            { order: 1, title: "Check for Successful Root Command Execution", group: "Investigation", tool: "query_siem_logs", desc: "Search for subsequent root-level commands executed after the SUID modification. Check for sudo, su, or direct root shell access." },
            { order: 2, title: "Get User Account Info", group: "Investigation", tool: "get_ad_user_info", desc: "Retrieve information on the user account that modified the SUID binary to determine if this is a service account or human user." },
            { order: 3, title: "Enrich File Hash via Cortex", group: "Enrichment", tool: "get_file_reputation", desc: "If the SUID binary has a known hash (from syscheck), submit it to Cortex VirusTotal to determine if it is a known exploit binary." },
            { order: 4, title: "Create TheHive Case", group: "Investigation", tool: "create_case", desc: "Open case using 'MITRE T1548.001' template. Include: affected binary path, old/new permissions, user. Severity: HIGH (3)." },
            { order: 5, title: "Isolate Endpoint if Root Shell Confirmed", group: "Containment", tool: "isolate_endpoint", desc: "If investigation confirms a successful root shell was obtained, isolate the endpoint immediately. Otherwise, remove SUID bit manually and monitor.", approval: "Wazuh host-deny after confirmed root escalation" },
            { order: 6, title: "Remove SUID Bit and Audit All SUID Binaries", group: "Remediation", tool: "add_case_note", desc: "Via Wazuh Active Response or manual intervention: chmod u-s on the affected binary. Run 'find / -perm /4000' to audit all SUID binaries on the host." },
            { order: 7, title: "Document and Close", group: "Reporting", tool: "update_case_status", desc: "Document: affected binary, user, root access achieved (yes/no), remediation steps taken. Update TheHive case status." }
        ]
    }
};

// Start initialization
document.addEventListener('DOMContentLoaded', () => {
    checkAuth();
    setupEventListeners();
});

// 1. Authentication Handlers
async function checkAuth() {
    try {
        const response = await fetch('/web/me');
        if (response.ok) {
            const userData = await response.json();
            showApp(userData);
        } else {
            showLogin();
        }
    } catch (error) {
        console.error('Auth check error:', error);
        showLogin();
    }
}

function showLogin() {
    loginContainer.classList.remove('hide');
    appContainer.classList.add('hide');
    loginError.classList.add('hide');
}

function showApp(user) {
    loginContainer.classList.add('hide');
    appContainer.classList.remove('hide');
    
    profileUsername.textContent = user.uid;
    profileRole.textContent = user.role === 'admin' ? 'SOC Administrator' : 'SOC Analyst';
    
    // Switch to dashboard and load statistics immediately
    switchView('dashboard');
    startPeriodicPolling();
}

// 2. Event Listeners Setup
function setupEventListeners() {
    // Login form submission
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const usernameInput = document.getElementById('username').value;
        const passwordInput = document.getElementById('password').value;
        
        try {
            const response = await fetch('/web/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: usernameInput, password: passwordInput })
            });
            
            if (response.ok) {
                await checkAuth();
            } else {
                const errData = await response.json();
                showLoginError(errData.detail || 'Authentication failed. Please check credentials.');
            }
        } catch (error) {
            showLoginError('Connection refused. Is the Gateway running?');
        }
    });

    // Logout click
    logoutBtn.addEventListener('click', async () => {
        try {
            await fetch('/web/logout', { method: 'POST' });
            activeSessionId = null;
            showLogin();
        } catch (error) {
            console.error('Logout error:', error);
        }
    });

    // New Session click
    newSessionBtn.addEventListener('click', () => {
        createNewSession();
    });

    // Session selection changed (Header Dropdown)
    sessionSelect.addEventListener('change', (e) => {
        const selectedId = e.target.value;
        if (selectedId) {
            openSessionDetail(selectedId);
        }
    });

    // Chat prompt submission
    detailChatForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const msg = chatInput.value.trim();
        if (!msg || isStreaming) return;
        
        chatInput.value = '';
        sendPrompt(msg);
    });

    // Tabs switching click handlers
    Object.keys(navItems).forEach(key => {
        if (navItems[key]) {
            navItems[key].addEventListener('click', (e) => {
                e.preventDefault();
                switchView(key);
            });
        }
    });

    // Dashboard Refresh Button
    if (dashboardRefreshBtn) {
        dashboardRefreshBtn.addEventListener('click', () => {
            loadDashboardData();
        });
    }

    // Sessions List Refresh Button
    if (sessionsRefreshBtn) {
        sessionsRefreshBtn.addEventListener('click', () => {
            loadSessionsList();
        });
    }

    // HITL Queue Refresh Button
    if (hitlRefreshBtn) {
        hitlRefreshBtn.addEventListener('click', () => {
            loadHitlQueue();
        });
    }

    // Back Button from detail view
    if (detailBackBtn) {
        detailBackBtn.addEventListener('click', () => {
            switchView('sessions');
        });
    }

    // Filter changes
    if (filterSource) filterSource.addEventListener('change', () => loadSessionsList());
    if (filterStatus) filterStatus.addEventListener('change', () => loadSessionsList());
    if (sessionsSearch) {
        sessionsSearch.addEventListener('input', debounce(() => {
            loadSessionsList();
        }, 300));
    }

    // Accordion Toggle for Raw Alert Payload
    if (rawAlertToggleHeader) {
        rawAlertToggleHeader.addEventListener('click', () => {
            const body = document.getElementById('raw-alert-body');
            body.classList.toggle('hide');
            const icon = rawAlertToggleHeader.querySelector('i');
            if (body.classList.contains('hide')) {
                icon.className = 'fa-solid fa-chevron-down text-muted';
            } else {
                icon.className = 'fa-solid fa-chevron-up text-muted';
            }
        });
    }

    // Personas Tab Agent Activation click
    if (agentsCardsContainer) {
        agentsCardsContainer.addEventListener('click', (e) => {
            const btn = e.target.closest('.activate-agent-btn');
            if (!btn) return;
            
            const agentId = btn.getAttribute('data-agent-id');
            activeAgent = agentId;
            loadAgents();
        });
    }

    // Playbook list item selection
    if (playbooksListContainer) {
        playbooksListContainer.addEventListener('click', (e) => {
            const item = e.target.closest('.playbook-item');
            if (!item) return;

            playbooksListContainer.querySelectorAll('.playbook-item').forEach(i => i.classList.remove('active-playbook'));
            item.classList.add('active-playbook');

            const id = item.getAttribute('data-playbook-id');
            showPlaybookDetails(id);
        });
    }

    // Settings Form submit
    if (settingsForm) {
        settingsForm.addEventListener('submit', (e) => {
            e.preventDefault();
            
            const coreUrl = document.getElementById('setting-core-url').value;
            const quota = document.getElementById('setting-quota').value;
            const retention = document.getElementById('setting-retention').value;
            const logLevel = document.getElementById('setting-log-level').value;

            localStorage.setItem('setting-core-url', coreUrl);
            localStorage.setItem('setting-quota', quota);
            localStorage.setItem('setting-retention', retention);
            localStorage.setItem('setting-log-level', logLevel);

            if (settingsSavedToast) {
                settingsSavedToast.classList.remove('hide');
                setTimeout(() => {
                    settingsSavedToast.classList.add('hide');
                }, 3000);
            }
        });
    }
}

function showLoginError(msg) {
    errorText.textContent = msg;
    loginError.classList.remove('hide');
}

// 3. Tab/View Switcher
function switchView(viewName) {
    // Update active nav link
    Object.keys(navItems).forEach(key => {
        if (navItems[key]) {
            if (key === viewName) {
                navItems[key].classList.add('active');
            } else {
                navItems[key].classList.remove('active');
            }
        }
    });

    // Update panel visibility
    Object.keys(panels).forEach(key => {
        if (panels[key]) {
            if (key === viewName) {
                panels[key].classList.remove('hide');
                panels[key].classList.add('active-panel');
            } else {
                panels[key].classList.add('hide');
                panels[key].classList.remove('active-panel');
            }
        }
    });

    // Load dynamic view contents
    if (viewName === 'dashboard') {
        viewTitle.textContent = "Security Orchestration Console";
        viewDesc.textContent = "Real-time autonomous incident investigation & threat enrichment";
        sessionControls.classList.remove('hide');
        loadDashboardData();
    } else if (viewName === 'sessions') {
        viewTitle.textContent = "SOC Investigation Sessions";
        viewDesc.textContent = "Monitor, filter, and review active and historic agent investigations";
        sessionControls.classList.add('hide');
        loadSessionsList();
    } else if (viewName === 'hitl') {
        viewTitle.textContent = "Human-in-the-Loop Queue";
        viewDesc.textContent = "Authorize or reject containment actions requested by autonomous workflows";
        sessionControls.classList.add('hide');
        loadHitlQueue();
    } else if (viewName === 'personas') {
        viewTitle.textContent = "Agent Personas Registry";
        viewDesc.textContent = "Configure, switch, and view capabilities of active security agent personas";
        sessionControls.classList.add('hide');
        loadAgents();
    } else if (viewName === 'playbooks') {
        viewTitle.textContent = "Incident Response Playbooks";
        viewDesc.textContent = "Browse mapped incident triage checklists and response procedures";
        sessionControls.classList.add('hide');
        loadPlaybooks();
    } else if (viewName === 'settings') {
        viewTitle.textContent = "System Configurations";
        viewDesc.textContent = "Manage endpoint connections, storage quotas, and security logging settings";
        sessionControls.classList.add('hide');
        loadSettingsForm();
    }
}

// 4. Data Loading - Dashboard View
async function loadDashboardData() {
    try {
        const statsRes = await fetch('/web/sessions/stats');
        if (statsRes.ok) {
            const stats = await statsRes.json();
            statActive.textContent = stats.active_sessions || 0;
            statHitl.textContent = stats.pending_hitl || 0;
            statToday.textContent = stats.created_last_24h || 0;
            statCompleted.textContent = stats.completed_sessions || 0;
            
            verdictTpCount.textContent = stats.true_positives || 0;
            verdictFpCount.textContent = stats.false_positives || 0;
            verdictUndCount.textContent = stats.undetermined || 0;
            
            const durationSec = Math.round(stats.avg_duration_seconds || 0);
            statAvgDuration.textContent = durationSec > 60 
                ? `${Math.floor(durationSec / 60)}m ${durationSec % 60}s` 
                : `${durationSec}s`;
                
            // Update HITL Sidebar count badge
            updateHitlBadge(stats.pending_hitl);
        }
        
        // Fetch 5 most recent sessions
        const recentRes = await fetch('/web/sessions?limit=5');
        if (recentRes.ok) {
            const sessions = await recentRes.json();
            renderRecentSessions(sessions);
            updateHeaderDropdown(sessions);
        }
    } catch (err) {
        console.error('Failed to load dashboard data:', err);
    }
}

function updateHitlBadge(count) {
    if (count > 0) {
        hitlBadgeCount.textContent = count;
        hitlBadgeCount.classList.remove('hide');
    } else {
        hitlBadgeCount.classList.add('hide');
    }
}

function renderRecentSessions(sessions) {
    if (!dashboardRecentList) return;
    
    if (!sessions || sessions.length === 0) {
        dashboardRecentList.innerHTML = `<div class="tree-empty">No sessions created yet. Start a new chat or trigger a SIEM alert.</div>`;
        return;
    }
    
    dashboardRecentList.innerHTML = '';
    sessions.forEach(sess => {
        const item = document.createElement('div');
        
        let priorityClass = 'priority-medium';
        if (sess.source === 'WAZUH') {
            const level = sess.wazuh_severity || 0;
            if (level >= 12) priorityClass = 'priority-critical';
            else if (level >= 8) priorityClass = 'priority-high';
            else if (level >= 4) priorityClass = 'priority-medium';
            else priorityClass = 'priority-low';
        }
        
        item.className = `alert-item ${priorityClass}`;
        
        const sourceBadge = sess.source === 'WAZUH' 
            ? `<span class="badge badge-error" style="background: rgba(239, 68, 68, 0.1); color: var(--error);">WAZUH</span>` 
            : `<span class="badge badge-success" style="background: rgba(34, 197, 94, 0.1); color: var(--secondary);">USER</span>`;
            
        const statusBadge = sess.status === 'WAITING_APPROVAL'
            ? `<span class="badge badge-warning" style="background: rgba(245, 158, 11, 0.15); color: var(--warning);">WAITING APPROVAL</span>`
            : sess.status === 'COMPLETED'
            ? `<span class="badge badge-success">COMPLETED</span>`
            : `<span class="badge badge-info">ACTIVE</span>`;
            
        const verdictBadge = sess.verdict && sess.verdict !== 'UNDETERMINED'
            ? `<span class="badge badge-info" style="font-size: 9px; margin-left: 5px;">${sess.verdict}</span>`
            : '';
            
        const dateStr = formatDate(sess.created_at);
        
        item.innerHTML = `
            <div class="alert-meta" style="margin-bottom: 6px;">
                <div style="display: flex; gap: 5px; align-items: center;">
                    ${sourceBadge}
                    ${statusBadge}
                    ${verdictBadge}
                </div>
                <span class="time">${dateStr}</span>
            </div>
            <h4 style="margin-bottom: 6px; font-size: 13.5px; color: var(--text-bright);">${sess.display_name}</h4>
            <div style="display: flex; justify-content: space-between; align-items: center; font-size: 11px; color: var(--text-muted);">
                <span>Agent: <strong class="text-cyan font-mono">${sess.agent_name || 'N/A'}</strong></span>
                <span>Tools Executed: <strong>${sess.tool_calls || 0}</strong></span>
            </div>
            <div style="margin-top: 10px; display: flex; justify-content: flex-end;">
                <button class="btn btn-secondary review-session-btn" data-session-id="${sess.id}" style="padding: 3px 8px; font-size: 11px;">
                    <span>Review Session</span>
                    <i class="fa-solid fa-arrow-right" style="font-size: 9px;"></i>
                </button>
            </div>
        `;
        
        // Bind Review Click
        item.querySelector('.review-session-btn').addEventListener('click', (e) => {
            e.stopPropagation();
            openSessionDetail(sess.id);
        });
        
        dashboardRecentList.appendChild(item);
    });
}

function updateHeaderDropdown(sessions) {
    sessionSelect.innerHTML = '<option value="">-- Select Active Session --</option>';
    sessions.forEach(sess => {
        const opt = document.createElement('option');
        opt.value = sess.id;
        opt.textContent = sess.display_name.length > 30 ? `${sess.display_name.substring(0, 30)}...` : sess.display_name;
        if (sess.id === activeSessionId) opt.selected = true;
        sessionSelect.appendChild(opt);
    });
}

// 5. Data Loading - Sessions List View
async function loadSessionsList() {
    try {
        const srcVal = filterSource.value;
        const statusVal = filterStatus.value;
        const searchVal = sessionsSearch.value.trim();
        
        let queryParams = [];
        if (srcVal) queryParams.push(`source=${srcVal}`);
        if (statusVal) queryParams.push(`status_filter=${statusVal}`);
        
        const url = `/web/sessions?${queryParams.join('&')}`;
        const res = await fetch(url);
        if (res.ok) {
            let sessions = await res.json();
            
            // Client-side search filtering
            if (searchVal) {
                const searchLower = searchVal.toLowerCase();
                sessions = sessions.filter(s => 
                    s.display_name.toLowerCase().includes(searchLower) ||
                    (s.source_ip && s.source_ip.toLowerCase().includes(searchLower)) ||
                    (s.wazuh_rule_id && s.wazuh_rule_id.toLowerCase().includes(searchLower))
                );
            }
            
            renderSessionsList(sessions);
        }
    } catch (err) {
        console.error('Failed to load sessions list:', err);
    }
}

function renderSessionsList(sessions) {
    if (!sessionsListContainer) return;
    
    if (!sessions || sessions.length === 0) {
        sessionsListContainer.innerHTML = `<div class="tree-empty">No sessions matching the filters found.</div>`;
        return;
    }
    
    sessionsListContainer.innerHTML = '';
    sessions.forEach(sess => {
        const card = document.createElement('div');
        
        let priorityClass = 'priority-medium';
        if (sess.source === 'WAZUH') {
            const level = sess.wazuh_severity || 0;
            if (level >= 12) priorityClass = 'priority-critical';
            else if (level >= 8) priorityClass = 'priority-high';
            else priorityClass = 'priority-low';
        }
        
        card.className = `glass-panel rounded-xl alert-item ${priorityClass}`;
        card.style.padding = '16px';
        card.style.cursor = 'default';
        
        const sourceBadge = sess.source === 'WAZUH' 
            ? `<span class="badge badge-error">WAZUH</span>` 
            : `<span class="badge badge-success">USER</span>`;
            
        const statusBadge = sess.status === 'WAITING_APPROVAL'
            ? `<span class="badge badge-warning">WAITING APPROVAL</span>`
            : sess.status === 'COMPLETED'
            ? `<span class="badge badge-success">COMPLETED</span>`
            : `<span class="badge badge-info">ACTIVE</span>`;
            
        const verdictBadge = sess.verdict && sess.verdict !== 'UNDETERMINED'
            ? `<span class="badge badge-info" style="margin-left: 5px;">${sess.verdict}</span>`
            : '';
            
        const dateStr = formatDate(sess.created_at);
        
        card.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 20px;">
                <div style="flex-grow: 1; min-width: 0;">
                    <div class="alert-meta" style="justify-content: flex-start; gap: 8px; margin-bottom: 6px;">
                        ${sourceBadge}
                        ${statusBadge}
                        ${verdictBadge}
                        <span class="time" style="margin-left: 5px;">${dateStr}</span>
                    </div>
                    <h4 style="font-size: 15px; font-weight: 600; color: var(--text-bright); margin-bottom: 8px;">${sess.display_name}</h4>
                    <div style="display: flex; gap: 20px; align-items: center; font-size: 12px; color: var(--text-muted); flex-wrap: wrap;">
                        <span>Agent: <strong class="text-cyan font-mono">${sess.agent_name || 'N/A'}</strong></span>
                        <span>Messages: <strong>${sess.message_count || 0}</strong></span>
                        <span>Tool Calls: <strong>${sess.tool_calls || 0}</strong></span>
                        <span>HITL Approvals: <strong>${sess.hitl_count || 0}</strong></span>
                    </div>
                </div>
                <div>
                    <button class="btn btn-secondary review-detail-btn" data-session-id="${sess.id}" style="padding: 6px 12px; font-size: 12px; white-space: nowrap;">
                        <span>View Details</span>
                        <i class="fa-solid fa-arrow-right"></i>
                    </button>
                </div>
            </div>
        `;
        
        card.querySelector('.review-detail-btn').addEventListener('click', () => {
            openSessionDetail(sess.id);
        });
        
        sessionsListContainer.appendChild(card);
    });
}

// 6. Data Loading - HITL Queue View
async function loadHitlQueue() {
    try {
        const res = await fetch('/web/sessions?status_filter=WAITING_APPROVAL');
        if (res.ok) {
            const hitlSessions = await res.json();
            renderHitlQueue(hitlSessions);
            updateHitlBadge(hitlSessions.length);
        }
    } catch (err) {
        console.error('Failed to load HITL queue:', err);
    }
}

function renderHitlQueue(sessions) {
    if (!hitlListContainer) return;
    
    if (!sessions || sessions.length === 0) {
        hitlListContainer.innerHTML = `<div class="tree-empty">No pending actions awaiting approval. Active alerts are fully automated.</div>`;
        return;
    }
    
    hitlListContainer.innerHTML = '';
    sessions.forEach(sess => {
        const card = document.createElement('div');
        card.className = 'glass-panel rounded-xl';
        card.style.padding = '16px';
        card.style.border = '1px solid var(--warning)';
        
        const dateStr = formatDate(sess.created_at);
        
        card.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 20px; margin-bottom: 12px;">
                <div>
                    <span class="badge badge-warning" style="margin-bottom: 6px;">WAITING APPROVAL</span>
                    <h4 style="font-size: 15px; font-weight: 600; color: var(--text-bright); margin-bottom: 4px; margin-top: 0;">${sess.display_name}</h4>
                    <span style="font-size: 11px; color: var(--text-muted);">Source IP: <strong class="text-cyan font-mono">${sess.source_ip || 'N/A'}</strong> | Rule ID: <strong class="font-mono">${sess.wazuh_rule_id || 'N/A'}</strong></span>
                </div>
                <span class="time" style="font-size: 11px; color: var(--text-muted);">${dateStr}</span>
            </div>
            
            <div style="background: rgba(0,0,0,0.3); border: 1px solid rgba(245, 158, 11, 0.2); padding: 12px; border-radius: 4px; margin-bottom: 15px;">
                <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 6px;">Requested Containment Action:</p>
                <div style="font-family: var(--font-mono); font-size: 12px; display: flex; flex-direction: column; gap: 4px;">
                    <div><span class="text-amber">ACTION:</span> <span class="text-bright font-bold" id="hitl-tool-${sess.id}">Loading action...</span></div>
                    <div><span class="text-amber">ARGUMENTS:</span></div>
                    <pre style="margin: 0; background: none; border: none; padding: 0; color: var(--text-main); font-size: 11px; overflow-x: auto;"><code id="hitl-args-${sess.id}">Loading parameters...</code></pre>
                </div>
            </div>
            
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <button class="btn btn-secondary inspect-session-btn" data-session-id="${sess.id}" style="font-size: 11px; padding: 4px 8px;">
                    <i class="fa-solid fa-magnifying-glass"></i> Inspect Session Logs
                </button>
                <div style="display: flex; gap: 10px;">
                    <button class="btn btn-muted quick-reject-btn" data-session-id="${sess.id}" style="padding: 6px 12px; font-size: 12px;">Reject</button>
                    <button class="btn btn-success quick-approve-btn" data-session-id="${sess.id}" style="padding: 6px 12px; font-size: 12px;">Approve</button>
                </div>
            </div>
        `;
        
        // Fetch event logs to extract the tool arguments requested for this specific session
        fetch(`/web/sessions/${sess.id}/events`)
            .then(res => res.json())
            .then(events => {
                // Find last event that represents a think/tool step requesting HITL
                const hitlEvent = events.slice().reverse().find(e => e.event_type === 'think' && e.metadata && e.metadata.tool_name);
                const toolEl = card.querySelector(`#hitl-tool-${sess.id}`);
                const argsEl = card.querySelector(`#hitl-args-${sess.id}`);
                
                if (hitlEvent) {
                    toolEl.textContent = hitlEvent.metadata.tool_name;
                    argsEl.textContent = typeof hitlEvent.metadata.tool_input === 'string' 
                        ? hitlEvent.metadata.tool_input 
                        : JSON.stringify(hitlEvent.metadata.tool_input, null, 2);
                } else {
                    toolEl.textContent = 'isolate_endpoint';
                    argsEl.textContent = JSON.stringify({ agent_id: sess.alert_payload?.data?.agent?.id || '1' }, null, 2);
                }
            })
            .catch(e => console.error('Failed to fetch events for HITL card:', e));
            
        card.querySelector('.inspect-session-btn').addEventListener('click', () => {
            openSessionDetail(sess.id);
        });
        
        card.querySelector('.quick-approve-btn').addEventListener('click', () => {
            submitHitlAction(sess.id, 'approve');
        });
        
        card.querySelector('.quick-reject-btn').addEventListener('click', () => {
            submitHitlAction(sess.id, 'reject');
        });
        
        hitlListContainer.appendChild(card);
    });
}

async function submitHitlAction(sessionId, action) {
    try {
        const statusVal = action === 'approve' ? 'COMPLETED' : 'FAILED';
        const verdictVal = action === 'approve' ? 'TRUE_POSITIVE' : 'FALSE_POSITIVE';
        
        const response = await fetch(`/web/sessions/${sessionId}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: statusVal, verdict: verdictVal })
        });
        
        if (response.ok) {
            // Reload
            if (panels.dashboard.classList.contains('active-panel')) {
                loadDashboardData();
            } else if (panels.sessions.classList.contains('active-panel')) {
                loadSessionsList();
            } else if (panels['session-detail'].classList.contains('active-panel')) {
                openSessionDetail(sessionId);
            } else {
                loadHitlQueue();
            }
        }
    } catch (err) {
        console.error('Failed to submit HITL action:', err);
    }
}

// 7. Session Detail Loader (Adaptive)
async function openSessionDetail(sessionId) {
    try {
        activeSessionId = sessionId;
        
        // Test auth by fetching details
        const detailsRes = await fetch(`/web/sessions/${sessionId}`);
        if (!detailsRes.ok) {
            throw new Error(`Failed to load session metadata: ${detailsRes.status}`);
        }
        const sess = await detailsRes.json();
        
        // Load Events
        const eventsRes = await fetch(`/web/sessions/${sessionId}/events`);
        const events = eventsRes.ok ? await eventsRes.ok && await eventsRes.json() : [];
        
        renderSessionDetails(sess, events);
    } catch (err) {
        console.error('Failed to open session detail view:', err);
    }
}

function renderSessionDetails(sess, events) {
    // Switch to panel
    switchView('session-detail');
    viewTitle.textContent = "Incident Triage Detail";
    viewDesc.textContent = `Detailed analysis of investigation session ${sess.id.substring(0,8)}...`;
    sessionControls.classList.add('hide');

    // Populate Headers
    detailDisplayName.textContent = sess.display_name;
    detailTimeBadge.textContent = `Created: ${formatDate(sess.created_at)}`;
    
    // Source Badge
    detailSourceBadge.className = sess.source === 'WAZUH' ? 'badge badge-error' : 'badge badge-success';
    detailSourceBadge.textContent = sess.source;
    
    // Status Badge
    let statusClass = 'badge-info';
    if (sess.status === 'COMPLETED') statusClass = 'badge-success';
    else if (sess.status === 'WAITING_APPROVAL') statusClass = 'badge-warning';
    else if (sess.status === 'FAILED') statusClass = 'badge-error';
    detailStatusBadge.className = `badge ${statusClass}`;
    detailStatusBadge.textContent = sess.status.replace('_', ' ');

    // Verdict Badge
    if (sess.verdict && sess.verdict !== 'UNDETERMINED') {
        detailVerdictBadge.className = sess.verdict === 'TRUE_POSITIVE' ? 'badge badge-error' : 'badge badge-success';
        detailVerdictBadge.textContent = sess.verdict.replace('_', ' ');
        detailVerdictBadge.classList.remove('hide');
    } else {
        detailVerdictBadge.classList.add('hide');
    }

    // Reset cards visibility
    detailWazuhCard.classList.add('hide');
    detailRawAlertCard.classList.add('hide');
    detailHitlCard.classList.add('hide');
    detailWorkspaceCard.classList.add('hide');
    detailChatInputCard.classList.add('hide');

    // Adaptive Side Panels depending on WAZUH vs USER source
    if (sess.source === 'WAZUH') {
        detailWazuhCard.classList.remove('hide');
        detailRawAlertCard.classList.remove('hide');
        
        // Fill Wazuh Details
        wazuhRuleId.textContent = sess.wazuh_rule_id || 'N/A';
        wazuhRuleLevel.textContent = sess.wazuh_severity || 'N/A';
        wazuhSrcIp.textContent = sess.source_ip || 'N/A';
        
        wazuhMitreIds.innerHTML = '';
        if (sess.mitre_ids && sess.mitre_ids.length > 0) {
            sess.mitre_ids.forEach(mid => {
                const chip = document.createElement('span');
                chip.className = 'tool-chip';
                chip.innerHTML = `<i class="fa-solid fa-tag"></i> ${mid}`;
                wazuhMitreIds.appendChild(chip);
            });
        } else {
            wazuhMitreIds.innerHTML = '<span class="text-muted">None</span>';
        }
        
        wazuhRawPayload.textContent = JSON.stringify(sess.alert_payload || {}, null, 2);
        
        // If status is WAITING_APPROVAL, display Authorization Card
        if (sess.status === 'WAITING_APPROVAL') {
            detailHitlCard.classList.remove('hide');
            
            // Look for pending action requested
            const hitlEvent = events.slice().reverse().find(e => e.event_type === 'think' && e.metadata && e.metadata.tool_name);
            if (hitlEvent) {
                detailHitlTool.textContent = hitlEvent.metadata.tool_name;
                detailHitlArgs.textContent = typeof hitlEvent.metadata.tool_input === 'string' 
                    ? hitlEvent.metadata.tool_input 
                    : JSON.stringify(hitlEvent.metadata.tool_input, null, 2);
            } else {
                detailHitlTool.textContent = 'isolate_endpoint';
                detailHitlArgs.textContent = JSON.stringify({ agent_id: sess.alert_payload?.data?.agent?.id || '1' }, null, 2);
            }
            
            detailHitlApprove.onclick = () => submitHitlAction(sess.id, 'approve');
            detailHitlReject.onclick = () => submitHitlAction(sess.id, 'reject');
        }
    } else if (sess.source === 'USER') {
        detailWorkspaceCard.classList.remove('hide');
        detailChatInputCard.classList.remove('hide');
        
        // Render Workspace Files
        renderWorkspaceFilesList(sess.id);
        
        // Handle detail chat input form submit
        detailChatForm.onsubmit = (e) => {
            e.preventDefault();
            const msg = chatInput.value.trim();
            if (!msg || isStreaming) return;
            
            chatInput.value = '';
            sendPrompt(msg);
        };
    }

    // Renders event logs timeline
    renderTimelineEvents(events);
}

function renderTimelineEvents(events) {
    if (!chatMessagesContainer) return;
    chatMessagesContainer.innerHTML = '';
    
    if (!events || events.length === 0) {
        chatMessagesContainer.innerHTML = `<div class="system-message"><p class="welcome-title">[ NO EVENTS LOGGED ]</p><p class="welcome-text">This session has no recorded audit log events.</p></div>`;
        return;
    }
    
    events.forEach(step => {
        const stepBlock = document.createElement('div');
        stepBlock.className = 'step-block';
        
        let headerHtml = '';
        let contentHtml = '';
        
        switch (step.event_type) {
            case 'think':
                headerHtml = `<div class="step-type-header step-thinking"><i class="fa-solid fa-brain"></i> THINKING (${step.actor})</div>`;
                contentHtml = `<div class="step-content text-cyan">${step.content}</div>`;
                break;
                
            case 'tool':
            case 'act':
                const toolName = step.metadata?.tool_name || 'system';
                headerHtml = `<div class="step-type-header step-tool"><i class="fa-solid fa-screwdriver-wrench"></i> EXECUTING TOOL: ${toolName}</div>`;
                let inputArgs = '';
                try {
                    const inp = step.metadata?.tool_input || step.content;
                    inputArgs = typeof inp === 'string' ? inp : JSON.stringify(inp, null, 2);
                } catch (e) { inputArgs = step.content; }
                contentHtml = `<div class="step-content"><pre><code>${inputArgs}</code></pre></div>`;
                break;
                
            case 'observe':
                headerHtml = `<div class="step-type-header step-observation"><i class="fa-solid fa-eye"></i> OBSERVATION</div>`;
                let outputText = '';
                try {
                    const out = step.metadata?.tool_output || step.content;
                    outputText = typeof out === 'string' ? out : JSON.stringify(out, null, 2);
                } catch (e) { outputText = step.content; }
                contentHtml = `<div class="step-content"><pre><code>${outputText}</code></pre></div>`;
                break;
                
            case 'answer':
            case 'message':
                if (step.actor === 'user') {
                    // Render User Message bubble
                    const userDiv = document.createElement('div');
                    userDiv.className = 'user-msg';
                    userDiv.textContent = step.content;
                    chatMessagesContainer.appendChild(userDiv);
                    return;
                } else {
                    headerHtml = `<div class="step-type-header step-answer"><i class="fa-solid fa-circle-check"></i> AGENT MESSAGE</div>`;
                    contentHtml = `<div class="step-content step-answer"><div class="step-content-inner">${step.content}</div></div>`;
                }
                break;
                
            case 'status_change':
                headerHtml = `<div class="step-type-header text-cyan"><i class="fa-solid fa-arrows-rotate"></i> AUDIT EVENT: STATUS CHANGED</div>`;
                contentHtml = `<div class="step-content text-muted">${step.content}</div>`;
                break;
                
            default:
                headerHtml = `<div class="step-type-header text-muted"><i class="fa-solid fa-clock"></i> EVENT: ${step.event_type.toUpperCase()}</div>`;
                contentHtml = `<div class="step-content">${step.content || ''}</div>`;
        }
        
        stepBlock.innerHTML = headerHtml + contentHtml;
        chatMessagesContainer.appendChild(stepBlock);
    });
    
    scrollTerminal();
}

async function renderWorkspaceFilesList(sessionId) {
    if (!detailWorkspaceFiles) return;
    
    try {
        const res = await fetch(`/v1/session/${sessionId}/workspace`);
        if (res.ok) {
            const data = await res.json();
            const usage = data.workspace;
            
            if (!usage || !usage.files || usage.files.length === 0) {
                detailWorkspaceFiles.innerHTML = `<div class="tree-empty">No files generated in workspace.</div>`;
                return;
            }
            
            detailWorkspaceFiles.innerHTML = '';
            usage.files.forEach(f => {
                const item = document.createElement('div');
                item.className = 'tree-item file';
                
                const isJson = f.name.endsWith('.json');
                const icon = isJson ? 'fa-file-code text-emerald' : 'fa-file-lines';
                
                item.innerHTML = `
                    <i class="fa-regular ${icon}"></i>
                    <span>${f.name} <span class="text-xs text-muted">(${f.size})</span></span>
                `;
                detailWorkspaceFiles.appendChild(item);
            });
        }
    } catch (err) {
        console.error('Failed to load workspace files:', err);
    }
}

// 8. Dynamic SSE Chat Prompts (USER Source)
async function sendPrompt(messageText) {
    if (isStreaming || !activeSessionId) return;
    isStreaming = true;
    
    // Add user message bubble
    const userDiv = document.createElement('div');
    userDiv.className = 'user-msg';
    userDiv.textContent = messageText;
    chatMessagesContainer.appendChild(userDiv);
    scrollTerminal();
    
    thinkingIndicator.classList.remove('hide');
    
    const payload = {
        message: messageText,
        agent: activeAgent,
        session_id: activeSessionId
    };
    
    try {
        const response = await fetch('/web/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        
        if (!response.ok) {
            throw new Error(`Chat API error: ${response.status}`);
        }
        
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';
        
        while (true) {
            const { value, done } = await reader.read();
            if (done) break;
            
            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split('\n\n');
            buffer = lines.pop();
            
            for (const line of lines) {
                if (line.startsWith('data: ')) {
                    const dataStr = line.replace('data: ', '').trim();
                    if (dataStr === '[DONE]') {
                        isStreaming = false;
                        thinkingIndicator.classList.add('hide');
                        break;
                    }
                    
                    try {
                        const parsed = JSON.parse(dataStr);
                        handleLiveStep(parsed);
                    } catch (e) {
                        console.error('Failed to parse SSE line:', e);
                    }
                }
            }
        }
    } catch (error) {
        console.error('Streaming error:', error);
        isStreaming = false;
        thinkingIndicator.classList.add('hide');
    }
}

function handleLiveStep(step) {
    thinkingIndicator.classList.add('hide');
    
    const stepBlock = document.createElement('div');
    stepBlock.className = 'step-block';
    
    let headerHtml = '';
    let contentHtml = '';
    
    switch (step.type) {
        case 'thought':
            headerHtml = `<div class="step-type-header step-thinking"><i class="fa-solid fa-brain"></i> THINKING</div>`;
            contentHtml = `<div class="step-content text-cyan">${step.content}</div>`;
            break;
            
        case 'tool':
            headerHtml = `<div class="step-type-header step-tool"><i class="fa-solid fa-screwdriver-wrench"></i> EXECUTING TOOL: ${step.tool || 'system'}</div>`;
            let inputArgs = '';
            try {
                inputArgs = typeof step.tool_input === 'string' ? step.tool_input : JSON.stringify(step.tool_input, null, 2);
            } catch (e) { inputArgs = step.tool_input; }
            contentHtml = `<div class="step-content"><pre><code>${inputArgs}</code></pre></div>`;
            break;
            
        case 'observation':
            headerHtml = `<div class="step-type-header step-observation"><i class="fa-solid fa-eye"></i> OBSERVATION</div>`;
            let outputText = '';
            try {
                outputText = typeof step.tool_output === 'string' ? step.tool_output : JSON.stringify(step.tool_output, null, 2);
            } catch (e) { outputText = step.tool_output; }
            contentHtml = `<div class="step-content"><pre><code>${outputText}</code></pre></div>`;
            break;
            
        case 'answer':
            headerHtml = `<div class="step-type-header step-answer"><i class="fa-solid fa-circle-check"></i> PROCESS COMPLETE</div>`;
            contentHtml = `<div class="step-content step-answer"><div class="step-content-inner">${step.content}</div></div>`;
            // Refresh workspace files since tool finished
            renderWorkspaceFilesList(activeSessionId);
            break;
            
        default:
            contentHtml = `<div class="step-content">${step.content || ''}</div>`;
    }
    
    stepBlock.innerHTML = headerHtml + contentHtml;
    chatMessagesContainer.appendChild(stepBlock);
    scrollTerminal();
}

// 9. Session Management (Create USER Session)
async function createNewSession() {
    try {
        const response = await fetch('/v1/session', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-Internal-Api-Key': 'dev-internal-key-change-me-in-production' // bypass core internal auth
            },
            body: JSON.stringify({ user_id: profileUsername.textContent || 'admin' })
        });
        
        if (response.ok) {
            const data = await response.json();
            openSessionDetail(data.session_id);
        }
    } catch (err) {
        console.error('Failed to create user session:', err);
    }
}

function scrollTerminal() {
    if (chatMessagesContainer) {
        chatMessagesContainer.scrollTop = chatMessagesContainer.scrollHeight;
    }
}

// 10. Personas Tab Handlers
async function loadAgents() {
    if (!agentsCardsContainer) return;
    
    agentsCardsContainer.innerHTML = `
        <div class="loading-state">
            <i class="fa-solid fa-spinner fa-spin text-cyan"></i> Loading registered agent personas...
        </div>
    `;

    try {
        const response = await fetch('/web/agents');
        if (!response.ok) {
            throw new Error(`Failed to load agents: ${response.status}`);
        }
        const agents = await response.json();
        renderAgents(agents);
    } catch (err) {
        console.error("Failed to load agents", err);
        agentsCardsContainer.innerHTML = `
            <div class="error-msg">
                <i class="fa-solid fa-triangle-exclamation"></i>
                <span>Failed to load agent personas: ${err.message}</span>
            </div>
        `;
    }
}

function renderAgents(agents) {
    if (!agentsCardsContainer) return;
    
    if (!agents || agents.length === 0) {
        agentsCardsContainer.innerHTML = `
            <div class="tree-empty">No agent personas registered.</div>
        `;
        return;
    }

    agentsCardsContainer.innerHTML = '';
    agents.forEach(agent => {
        const isActive = agent.id === activeAgent;
        const card = document.createElement('div');
        card.className = `agent-card glass-panel ${isActive ? 'active-agent-card' : ''}`;
        
        const toolChips = agent.tools && agent.tools.length > 0
            ? agent.tools.map(t => `<span class="tool-chip"><i class="fa-solid fa-square-poll-horizontal"></i> ${t}</span>`).join('')
            : '<span class="tool-chip text-muted">None</span>';

        card.innerHTML = `
            <div class="agent-card-header">
                <div class="agent-avatar">
                    <i class="fa-solid fa-robot"></i>
                </div>
                <div class="agent-meta">
                    <h4>${agent.name || agent.id}</h4>
                    <span class="agent-id font-mono">${agent.id}</span>
                </div>
                ${isActive ? '<span class="badge badge-success">ACTIVE</span>' : ''}
            </div>
            <p class="agent-desc">${agent.role || 'No description provided.'}</p>
            <div class="agent-specs">
                <div class="spec-item">
                    <span class="label">MODEL:</span>
                    <span class="val font-mono">${agent.model || 'unknown'}</span>
                </div>
                <div class="spec-item">
                    <span class="label">TEMP:</span>
                    <span class="val font-mono">${agent.temperature !== undefined ? agent.temperature : '0.0'}</span>
                </div>
            </div>
            <div class="agent-tools">
                <span class="label">ALLOWED TOOLS:</span>
                <div class="tool-chips">
                    ${toolChips}
                </div>
            </div>
            <div class="agent-card-footer">
                ${isActive
                    ? `<button class="btn btn-secondary btn-block" disabled><i class="fa-solid fa-circle-check"></i> CURRENTLY ACTIVE</button>`
                    : `<button class="btn btn-primary btn-block activate-agent-btn" data-agent-id="${agent.id}">ACTIVATE PERSONA</button>`
                }
            </div>
        `;
        agentsCardsContainer.appendChild(card);
    });
}

// 11. Playbooks Tab Handlers
let playbooksCache = [];

async function loadPlaybooks() {
    if (!playbooksListContainer) return;
    
    playbooksListContainer.innerHTML = `
        <div class="loading-state">
            <i class="fa-solid fa-spinner fa-spin text-cyan"></i> Loading...
        </div>
    `;

    try {
        const response = await fetch('/web/playbooks');
        if (!response.ok) {
            throw new Error(`Failed to load playbooks: ${response.status}`);
        }
        const data = await response.json();
        
        playbooksCache = parsePlaybooksMarkdown(data.markdown || '');
        renderPlaybooksList(playbooksCache);
    } catch (err) {
        console.error("Failed to load playbooks", err);
        playbooksListContainer.innerHTML = `
            <div class="error-msg">
                <i class="fa-solid fa-triangle-exclamation"></i>
                <span>Failed: ${err.message}</span>
            </div>
        `;
    }
}

function parsePlaybooksMarkdown(markdown) {
    const playbooks = [];
    const blocks = markdown.split(/\n(?=\*\*PB-)/);
    
    blocks.forEach(block => {
        const titleMatch = block.match(/^\*\*([a-zA-Z0-9_-]+)\*\*\s*[-–]\s*([^\n]+)/m);
        if (titleMatch) {
            const id = titleMatch[1].trim();
            const name = titleMatch[2].trim();
            
            let mitre = '';
            let severity = 'MEDIUM';
            let steps = 0;
            
            const metaMatch = block.match(/MITRE:\s*([^|]+)\|\s*Severity:\s*([^|]+)\|\s*Step:\s*(\d+)/i);
            if (metaMatch) {
                mitre = metaMatch[1].trim();
                severity = metaMatch[2].trim();
                steps = parseInt(metaMatch[3].trim(), 10);
            } else {
                const simpleMetaMatch = block.match(/MITRE:\s*([^|]+)\|\s*Severity:\s*([^\n]+)/i);
                if (simpleMetaMatch) {
                    mitre = simpleMetaMatch[1].trim();
                    severity = simpleMetaMatch[2].trim();
                }
            }
            
            playbooks.push({ id, name, mitre, severity, steps });
        }
    });
    
    return playbooks;
}

function renderPlaybooksList(playbooks) {
    if (!playbooksListContainer) return;

    if (!playbooks || playbooks.length === 0) {
        playbooksListContainer.innerHTML = `<div class="tree-empty">No playbooks found in triage registry.</div>`;
        return;
    }

    playbooksListContainer.innerHTML = '';
    playbooks.forEach(pb => {
        const item = document.createElement('div');
        item.className = 'playbook-item';
        item.setAttribute('data-playbook-id', pb.id);
        
        let badgeClass = 'badge-info';
        if (pb.severity.toUpperCase() === 'CRITICAL') badgeClass = 'badge-error';
        else if (pb.severity.toUpperCase() === 'HIGH') badgeClass = 'badge-warning';
        else if (pb.severity.toUpperCase() === 'LOW') badgeClass = 'badge-muted';
        
        item.innerHTML = `
            <div class="playbook-item-header">
                <span class="playbook-id-badge">${pb.id}</span>
                <span class="badge ${badgeClass}">${pb.severity}</span>
            </div>
            <div class="playbook-name">${pb.name}</div>
            <div class="playbook-meta-line">
                MITRE: ${pb.mitre || 'N/A'} | Steps: ${pb.steps || '0'}
            </div>
        `;
        playbooksListContainer.appendChild(item);
    });
}

function showPlaybookDetails(id) {
    if (!playbooksMarkdownViewer) return;

    const pb = PLAYBOOK_CATALOG[id];
    if (!pb) {
        playbooksMarkdownViewer.innerHTML = `
            <div class="welcome-message">
                <i class="fa-solid fa-triangle-exclamation text-error placeholder-icon"></i>
                <p>Playbook steps for ${id} are not defined in the local UI catalog.</p>
            </div>
        `;
        return;
    }

    let badgeClass = 'badge-info';
    if (pb.severity.toUpperCase() === 'CRITICAL') badgeClass = 'badge-error';
    else if (pb.severity.toUpperCase() === 'HIGH') badgeClass = 'badge-warning';
    else if (pb.severity.toUpperCase() === 'LOW') badgeClass = 'badge-muted';

    const mitreTags = pb.mitre_ids.map(mid => `<span class="tool-chip"><i class="fa-solid fa-tag"></i> ${mid}</span>`).join(' ');

    let stepsHtml = '';
    pb.steps.forEach(step => {
        const groupClass = `group-${step.group.toLowerCase()}`;
        stepsHtml += `
            <div class="timeline-step ${step.approval ? 'step-requires-approval' : ''}">
                <div class="timeline-step-node"></div>
                <div class="timeline-step-content">
                    <div class="step-meta">
                        <span class="step-num-title">Step ${step.order + 1}: ${step.title}</span>
                        <span class="step-group-badge ${groupClass}">${step.group}</span>
                    </div>
                    <p class="step-description">${step.desc}</p>
                    <div class="step-footer-row">
                        <span class="step-tool-hint"><i class="fa-solid fa-screwdriver-wrench"></i> ${step.tool}</span>
                        ${step.approval
                            ? `<span class="step-approval-warning"><i class="fa-solid fa-triangle-exclamation"></i> Approval: ${step.approval}</span>`
                            : ''
                        }
                    </div>
                </div>
            </div>
        `;
    });

    playbooksMarkdownViewer.innerHTML = `
        <div class="playbook-detail-header">
            <h3>[${pb.id}] ${pb.name}</h3>
            <div class="playbook-detail-meta">
                <span class="badge ${badgeClass}">${pb.severity} Severity</span>
                ${mitreTags}
            </div>
        </div>
        <p class="playbook-detail-desc">${pb.description}</p>
        <div class="timeline-title">REACTION SEQUENCE TIMELINE</div>
        <div class="playbook-timeline">
            ${stepsHtml}
        </div>
    `;
}

// 12. Settings Tab Handlers
function loadSettingsForm() {
    const coreUrl = localStorage.getItem('setting-core-url') || 'http://agentix-api:8000';
    const quota = localStorage.getItem('setting-quota') || '100';
    const retention = localStorage.getItem('setting-retention') || '30';
    const logLevel = localStorage.getItem('setting-log-level') || 'DEBUG';

    const coreUrlInput = document.getElementById('setting-core-url');
    const quotaInput = document.getElementById('setting-quota');
    const retentionInput = document.getElementById('setting-retention');
    const logLevelSelect = document.getElementById('setting-log-level');

    if (coreUrlInput) coreUrlInput.value = coreUrl;
    if (quotaInput) quotaInput.value = quota;
    if (retentionInput) retentionInput.value = retention;
    if (logLevelSelect) logLevelSelect.value = logLevel;
}

// 13. Polling and Utility Helpers
function startPeriodicPolling() {
    // Poll stats and active alerts every 10 seconds
    setInterval(() => {
        if (panels.dashboard.classList.contains('active-panel')) {
            loadDashboardData();
        } else if (panels.hitl.classList.contains('active-panel')) {
            loadHitlQueue();
        }
    }, 10000);
}

function formatDate(isoStr) {
    if (!isoStr) return '';
    try {
        const d = new Date(isoStr);
        return d.toLocaleDateString('en-US', { month: 'short', day: '2-digit' }) + ' ' + 
               d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
    } catch(e) {
        return isoStr;
    }
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}
