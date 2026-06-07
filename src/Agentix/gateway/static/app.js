/**
 * Agentix Web UI Core JavaScript Logic
 * Implements Obsidian Sentinel design system client.
 */

// Application State
let activeSessionId = null;
let activeAgent = 'soc_analyst';
let isStreaming = false;
const activeSessionsList = new Set();
const processingSessions = new Set();

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

// Pagination DOM Elements
const dashboardPrevBtn = document.getElementById('dashboard-prev-btn');
const dashboardNextBtn = document.getElementById('dashboard-next-btn');
const dashboardPageInfo = document.getElementById('dashboard-page-info');
const dashboardLimitSelect = document.getElementById('dashboard-limit-select');

const sessionsPrevBtn = document.getElementById('sessions-prev-btn');
const sessionsNextBtn = document.getElementById('sessions-next-btn');
const sessionsPageInfo = document.getElementById('sessions-page-info');
const sessionsLimitSelect = document.getElementById('sessions-limit-select');

const hitlPrevBtn = document.getElementById('hitl-prev-btn');
const hitlNextBtn = document.getElementById('hitl-next-btn');
const hitlPageInfo = document.getElementById('hitl-page-info');
const hitlLimitSelect = document.getElementById('hitl-limit-select');

// Pagination State
let dashboardPage = 1;
let dashboardPageSize = 20;
let dashboardSessionsList = [];
let dashboardTotalCount = 0;

let sessionsPage = 1;
let sessionsPageSize = 20;
let sessionsFullList = [];
let sessionsTotalCount = 0;

let hitlPage = 1;
let hitlPageSize = 20;
let hitlFullList = [];
let hitlTotalCount = 0;

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
const detailRefreshBtn = document.getElementById('detail-refresh-btn');
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
const detailHitlJustification = document.getElementById('detail-hitl-justification');

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
        
        const submitBtn = loginForm.querySelector('button[type="submit"]');
        const originalBtnHtml = submitBtn.innerHTML;
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<span>INITIALIZING…</span> <i class="fa-solid fa-spinner fa-spin" aria-hidden="true"></i>';
        
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
                submitBtn.disabled = false;
                submitBtn.innerHTML = originalBtnHtml;
            }
        } catch (error) {
            showLoginError('Connection refused. Is the Gateway running?');
            submitBtn.disabled = false;
            submitBtn.innerHTML = originalBtnHtml;
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
        dashboardRefreshBtn.addEventListener('click', async () => {
            await fetchWithLoader(
                { buttons: [dashboardRefreshBtn], container: dashboardRecentList },
                async () => {
                    await loadDashboardData();
                }
            );
        });
    }

    // Sessions List Refresh Button
    if (sessionsRefreshBtn) {
        sessionsRefreshBtn.addEventListener('click', async () => {
            await fetchWithLoader(
                { buttons: [sessionsRefreshBtn], container: sessionsListContainer },
                async () => {
                    await loadSessionsList();
                }
            );
        });
    }

    // HITL Queue Refresh Button
    if (hitlRefreshBtn) {
        hitlRefreshBtn.addEventListener('click', async () => {
            await fetchWithLoader(
                { buttons: [hitlRefreshBtn], container: hitlListContainer },
                async () => {
                    await loadHitlQueue();
                }
            );
        });
    }

    // Back Button from detail view
    if (detailBackBtn) {
        detailBackBtn.addEventListener('click', () => {
            switchView('sessions');
        });
    }

    // Refresh Button from detail view
    if (detailRefreshBtn) {
        detailRefreshBtn.addEventListener('click', async () => {
            if (activeSessionId) {
                await fetchWithLoader(
                    { buttons: [detailRefreshBtn], container: document.getElementById('detail-timeline') },
                    async () => {
                        await openSessionDetail(activeSessionId);
                    }
                );
            }
        });
    }

    // Filter changes
    if (filterSource) {
        filterSource.addEventListener('change', async () => {
            await fetchWithLoader(
                { buttons: [sessionsPrevBtn, sessionsNextBtn, sessionsLimitSelect], container: sessionsListContainer },
                async () => {
                    await loadSessionsList();
                }
            );
        });
    }
    if (filterStatus) {
        filterStatus.addEventListener('change', async () => {
            await fetchWithLoader(
                { buttons: [sessionsPrevBtn, sessionsNextBtn, sessionsLimitSelect], container: sessionsListContainer },
                async () => {
                    await loadSessionsList();
                }
            );
        });
    }
    if (sessionsSearch) {
        sessionsSearch.addEventListener('input', debounce(async () => {
            await fetchWithLoader(
                { buttons: [sessionsPrevBtn, sessionsNextBtn, sessionsLimitSelect], container: sessionsListContainer },
                async () => {
                    await loadSessionsList();
                }
            );
        }, 300));
    }

    // Pagination event listeners
    if (dashboardPrevBtn) {
        dashboardPrevBtn.addEventListener('click', async () => {
            if (dashboardPage > 1) {
                await fetchWithLoader(
                    { buttons: [dashboardPrevBtn, dashboardNextBtn, dashboardLimitSelect], container: dashboardRecentList },
                    async () => {
                        dashboardPage--;
                        await loadDashboardSessions();
                    }
                );
            }
        });
    }
    if (dashboardNextBtn) {
        dashboardNextBtn.addEventListener('click', async () => {
            const maxPage = Math.ceil(dashboardTotalCount / dashboardPageSize) || 1;
            if (dashboardPage < maxPage) {
                await fetchWithLoader(
                    { buttons: [dashboardPrevBtn, dashboardNextBtn, dashboardLimitSelect], container: dashboardRecentList },
                    async () => {
                        dashboardPage++;
                        await loadDashboardSessions();
                    }
                );
            }
        });
    }

    if (sessionsPrevBtn) {
        sessionsPrevBtn.addEventListener('click', async () => {
            if (sessionsPage > 1) {
                await fetchWithLoader(
                    { buttons: [sessionsPrevBtn, sessionsNextBtn, sessionsLimitSelect], container: sessionsListContainer },
                    async () => {
                        sessionsPage--;
                        await loadSessionsList(false);
                    }
                );
            }
        });
    }
    if (sessionsNextBtn) {
        sessionsNextBtn.addEventListener('click', async () => {
            const maxPage = Math.ceil(sessionsTotalCount / sessionsPageSize) || 1;
            if (sessionsPage < maxPage) {
                await fetchWithLoader(
                    { buttons: [sessionsPrevBtn, sessionsNextBtn, sessionsLimitSelect], container: sessionsListContainer },
                    async () => {
                        sessionsPage++;
                        await loadSessionsList(false);
                    }
                );
            }
        });
    }

    if (hitlPrevBtn) {
        hitlPrevBtn.addEventListener('click', async () => {
            if (hitlPage > 1) {
                await fetchWithLoader(
                    { buttons: [hitlPrevBtn, hitlNextBtn, hitlLimitSelect], container: hitlListContainer },
                    async () => {
                        hitlPage--;
                        await loadHitlQueue(false);
                    }
                );
            }
        });
    }
    if (hitlNextBtn) {
        hitlNextBtn.addEventListener('click', async () => {
            const maxPage = Math.ceil(hitlTotalCount / hitlPageSize) || 1;
            if (hitlPage < maxPage) {
                await fetchWithLoader(
                    { buttons: [hitlPrevBtn, hitlNextBtn, hitlLimitSelect], container: hitlListContainer },
                    async () => {
                        hitlPage++;
                        await loadHitlQueue(false);
                    }
                );
            }
        });
    }

    // Limit (page size) selectors
    if (dashboardLimitSelect) {
        dashboardLimitSelect.addEventListener('change', async (e) => {
            await fetchWithLoader(
                { buttons: [dashboardPrevBtn, dashboardNextBtn, dashboardLimitSelect], container: dashboardRecentList },
                async () => {
                    dashboardPageSize = parseInt(e.target.value);
                    dashboardPage = 1;
                    await loadDashboardSessions();
                }
            );
        });
    }
    if (sessionsLimitSelect) {
        sessionsLimitSelect.addEventListener('change', async (e) => {
            await fetchWithLoader(
                { buttons: [sessionsPrevBtn, sessionsNextBtn, sessionsLimitSelect], container: sessionsListContainer },
                async () => {
                    sessionsPageSize = parseInt(e.target.value);
                    sessionsPage = 1;
                    await loadSessionsList(true);
                }
            );
        });
    }
    if (hitlLimitSelect) {
        hitlLimitSelect.addEventListener('change', async (e) => {
            await fetchWithLoader(
                { buttons: [hitlPrevBtn, hitlNextBtn, hitlLimitSelect], container: hitlListContainer },
                async () => {
                    hitlPageSize = parseInt(e.target.value);
                    hitlPage = 1;
                    await loadHitlQueue(true);
                }
            );
        });
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

    // Accordion Toggle for HITL Technical Details
    const hitlTechnicalToggle = document.getElementById('hitl-technical-toggle');
    if (hitlTechnicalToggle) {
        hitlTechnicalToggle.addEventListener('click', () => {
            const body = document.getElementById('hitl-technical-body');
            body.classList.toggle('hide');
            const icon = hitlTechnicalToggle.querySelector('.fa-chevron-down, .fa-chevron-up');
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
        viewTitle.textContent = "Incident Triage Sessions";
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
        
        // Fetch recent sessions for header dropdown and filter to show only active ones
        const recentRes = await fetch('/web/sessions?limit=100');
        if (recentRes.ok) {
            const data = await recentRes.json();
            const dropdownList = data.sessions || [];
            const activeOnly = dropdownList.filter(sess => sess.status === 'ACTIVE' || sess.status === 'WAITING_APPROVAL');
            updateHeaderDropdown(activeOnly);
        }

        dashboardPage = 1;
        await loadDashboardSessions();
    } catch (err) {
        console.error('Failed to load dashboard data:', err);
    }
}

async function loadDashboardSessions() {
    try {
        const offset = (dashboardPage - 1) * dashboardPageSize;
        const res = await fetch(`/web/sessions?limit=${dashboardPageSize}&offset=${offset}`);
        if (res.ok) {
            const data = await res.json();
            dashboardTotalCount = data.total_count || 0;
            dashboardSessionsList = data.sessions || [];
            renderRecentSessionsPage();
        }
    } catch (err) {
        console.error('Failed to load dashboard sessions:', err);
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

function renderRecentSessionsPage() {
    if (!dashboardRecentList) return;
    
    if (!dashboardSessionsList || dashboardSessionsList.length === 0) {
        dashboardRecentList.innerHTML = `<div class="tree-empty">No sessions created yet. Start a new chat or trigger a SIEM alert.</div>`;
        if (dashboardPageInfo) dashboardPageInfo.textContent = "Showing 0–0 of 0";
        if (dashboardPrevBtn) dashboardPrevBtn.disabled = true;
        if (dashboardNextBtn) dashboardNextBtn.disabled = true;
        return;
    }
    
    const maxPage = Math.ceil(dashboardTotalCount / dashboardPageSize) || 1;
    if (dashboardPage > maxPage) dashboardPage = maxPage;
    if (dashboardPage < 1) dashboardPage = 1;
    
    if (dashboardPageInfo) {
        const startItem = dashboardTotalCount === 0 ? 0 : (dashboardPage - 1) * dashboardPageSize + 1;
        const endItem = Math.min(dashboardPage * dashboardPageSize, dashboardTotalCount);
        dashboardPageInfo.textContent = `Showing ${startItem}–${endItem} of ${dashboardTotalCount}`;
    }
    if (dashboardPrevBtn) dashboardPrevBtn.disabled = dashboardPage === 1;
    if (dashboardNextBtn) dashboardNextBtn.disabled = dashboardPage === maxPage;
    
    const pageItems = dashboardSessionsList;
    
    dashboardRecentList.innerHTML = '';
    pageItems.forEach(sess => {
        const item = document.createElement('div');
        
        let priorityClass = 'priority-medium';
        if (sess.source === 'SIEM') {
            const level = sess.siem_severity || 0;
            if (level >= 12) priorityClass = 'priority-critical';
            else if (level >= 8) priorityClass = 'priority-high';
            else if (level >= 4) priorityClass = 'priority-medium';
            else priorityClass = 'priority-low';
        }
        
        item.className = `alert-item ${priorityClass}`;
        
        const sourceBadge = sess.source === 'SIEM' 
            ? `<span class="badge badge-error recent-source-siem">SIEM</span>` 
            : `<span class="badge badge-success recent-source-user">USER</span>`;
            
        const statusBadge = sess.status === 'WAITING_APPROVAL'
            ? `<span class="badge badge-warning recent-status-waiting">WAITING APPROVAL</span>`
            : sess.status === 'COMPLETED'
            ? `<span class="badge badge-success">COMPLETED</span>`
            : `<span class="badge badge-info">ACTIVE</span>`;
            
        const verdictBadge = sess.verdict && sess.verdict !== 'UNDETERMINED'
            ? `<span class="badge badge-info recent-verdict-badge">${sess.verdict}</span>`
            : '';
            
        const dateStr = formatDate(sess.created_at);
        
        item.innerHTML = `
            <div class="alert-meta alert-meta-container">
                <div class="badge-container-row">
                    ${sourceBadge}
                    ${statusBadge}
                    ${verdictBadge}
                </div>
                <span class="time">${dateStr}</span>
            </div>
            <h4 class="recent-title">${sess.display_name}</h4>
            <div class="recent-info-row">
                <span>Agent: <strong class="text-cyan font-mono">${sess.agent_name || 'N/A'}</strong></span>
                <span>Tools Executed: <strong>${sess.tool_calls || 0}</strong></span>
            </div>
            <div class="recent-action-row">
                <button class="btn btn-secondary review-session-btn btn-xs-padding-review" data-session-id="${sess.id}">
                    <span>Review Session</span>
                    <i class="fa-solid fa-arrow-right icon-arrow-xs" aria-hidden="true"></i>
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
        opt.textContent = sess.display_name.length > 30 ? `${sess.display_name.substring(0, 30)}…` : sess.display_name;
        if (sess.id === activeSessionId) opt.selected = true;
        sessionSelect.appendChild(opt);
    });
}

// 5. Data Loading - Sessions List View
async function loadSessionsList(resetPage = true) {
    try {
        if (resetPage) {
            sessionsPage = 1;
        }
        const srcVal = filterSource.value;
        const statusVal = filterStatus.value;
        const searchVal = sessionsSearch.value.trim();
        
        let queryParams = [];
        if (srcVal) queryParams.push(`source=${srcVal}`);
        if (statusVal) queryParams.push(`status_filter=${statusVal}`);
        if (searchVal) queryParams.push(`search=${encodeURIComponent(searchVal)}`);
        
        const offset = (sessionsPage - 1) * sessionsPageSize;
        queryParams.push(`limit=${sessionsPageSize}`);
        queryParams.push(`offset=${offset}`);
        
        const url = `/web/sessions?${queryParams.join('&')}`;
        const res = await fetch(url);
        if (res.ok) {
            const data = await res.json();
            sessionsTotalCount = data.total_count || 0;
            sessionsFullList = data.sessions || [];
            renderSessionsListPage();
        }
    } catch (err) {
        console.error('Failed to load sessions list:', err);
    }
}

function renderSessionsListPage() {
    if (!sessionsListContainer) return;
    
    if (!sessionsFullList || sessionsFullList.length === 0) {
        sessionsListContainer.innerHTML = `<div class="tree-empty">No sessions matching the filters found.</div>`;
        if (sessionsPageInfo) sessionsPageInfo.textContent = "Showing 0–0 of 0";
        if (sessionsPrevBtn) sessionsPrevBtn.disabled = true;
        if (sessionsNextBtn) sessionsNextBtn.disabled = true;
        return;
    }
    
    const maxPage = Math.ceil(sessionsTotalCount / sessionsPageSize) || 1;
    if (sessionsPage > maxPage) sessionsPage = maxPage;
    if (sessionsPage < 1) sessionsPage = 1;
    
    if (sessionsPageInfo) {
        const startItem = sessionsTotalCount === 0 ? 0 : (sessionsPage - 1) * sessionsPageSize + 1;
        const endItem = Math.min(sessionsPage * sessionsPageSize, sessionsTotalCount);
        sessionsPageInfo.textContent = `Showing ${startItem}–${endItem} of ${sessionsTotalCount}`;
    }
    if (sessionsPrevBtn) sessionsPrevBtn.disabled = sessionsPage === 1;
    if (sessionsNextBtn) sessionsNextBtn.disabled = sessionsPage === maxPage;
    
    const pageItems = sessionsFullList;
    
    sessionsListContainer.innerHTML = '';
    pageItems.forEach(sess => {
        const card = document.createElement('div');
        
        let priorityClass = 'priority-medium';
        if (sess.source === 'SIEM') {
            const level = sess.siem_severity || 0;
            if (level >= 12) priorityClass = 'priority-critical';
            else if (level >= 8) priorityClass = 'priority-high';
            else priorityClass = 'priority-low';
        }
        
        card.className = `glass-panel alert-item ${priorityClass}`;
        
        const sourceBadge = sess.source === 'SIEM' 
            ? `<span class="badge badge-error">SIEM</span>` 
            : `<span class="badge badge-success">USER</span>`;
            
        const statusBadge = sess.status === 'WAITING_APPROVAL'
            ? `<span class="badge badge-warning">WAITING APPROVAL</span>`
            : sess.status === 'COMPLETED'
            ? `<span class="badge badge-success">COMPLETED</span>`
            : `<span class="badge badge-info">ACTIVE</span>`;
            
        const verdictBadge = sess.verdict && sess.verdict !== 'UNDETERMINED'
            ? `<span class="badge badge-info session-item-date">${sess.verdict}</span>`
            : '';
            
        const dateStr = formatDate(sess.created_at);
        
        card.innerHTML = `
            <div class="session-item-layout">
                <div class="session-item-content-wrapper">
                    <div class="alert-meta session-item-meta">
                        ${sourceBadge}
                        ${statusBadge}
                        ${verdictBadge}
                        <span class="time session-item-date">${dateStr}</span>
                    </div>
                    <h4 class="session-item-title">${sess.display_name}</h4>
                    <div class="session-item-details-row">
                        <span>Agent: <strong class="text-cyan font-mono">${sess.agent_name || 'N/A'}</strong></span>
                        <span>Messages: <strong>${sess.message_count || 0}</strong></span>
                        <span>Tool Calls: <strong>${sess.tool_calls || 0}</strong></span>
                        <span>HITL Approvals: <strong>${sess.hitl_count || 0}</strong></span>
                    </div>
                </div>
                <div>
                    <button class="btn btn-secondary review-detail-btn review-detail-btn-padding" data-session-id="${sess.id}">
                        <span>View Details</span>
                        <i class="fa-solid fa-arrow-right" aria-hidden="true"></i>
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
async function loadHitlQueue(resetPage = true) {
    try {
        if (resetPage) {
            hitlPage = 1;
        }
        const offset = (hitlPage - 1) * hitlPageSize;
        const res = await fetch(`/web/sessions?status_filter=WAITING_APPROVAL&limit=${hitlPageSize}&offset=${offset}`);
        if (res.ok) {
            const data = await res.json();
            hitlTotalCount = data.total_count || 0;
            hitlFullList = data.sessions || [];
            renderHitlQueuePage();
            updateHitlBadge(hitlTotalCount);
        }
    } catch (err) {
        console.error('Failed to load HITL queue:', err);
    }
}

function renderHitlQueuePage() {
    if (!hitlListContainer) return;
    
    if (!hitlFullList || hitlFullList.length === 0) {
        hitlListContainer.innerHTML = `<div class="tree-empty">No pending actions awaiting approval. Active alerts are fully automated.</div>`;
        if (hitlPageInfo) hitlPageInfo.textContent = "Showing 0–0 of 0";
        if (hitlPrevBtn) hitlPrevBtn.disabled = true;
        if (hitlNextBtn) hitlNextBtn.disabled = true;
        return;
    }
    
    const maxPage = Math.ceil(hitlTotalCount / hitlPageSize) || 1;
    if (hitlPage > maxPage) hitlPage = maxPage;
    if (hitlPage < 1) hitlPage = 1;
    
    if (hitlPageInfo) {
        const startItem = hitlTotalCount === 0 ? 0 : (hitlPage - 1) * hitlPageSize + 1;
        const endItem = Math.min(hitlPage * hitlPageSize, hitlTotalCount);
        hitlPageInfo.textContent = `Showing ${startItem}–${endItem} of ${hitlTotalCount}`;
    }
    if (hitlPrevBtn) hitlPrevBtn.disabled = hitlPage === 1;
    if (hitlNextBtn) hitlNextBtn.disabled = hitlPage === maxPage;
    
    const pageItems = hitlFullList;
    
    hitlListContainer.innerHTML = '';
    pageItems.forEach(sess => {
        const card = document.createElement('div');
        card.className = 'glass-panel hitl-warning-card';
        
        const dateStr = formatDate(sess.created_at);
        
        card.innerHTML = `
            <div class="hitl-item-header">
                <div>
                    <span class="badge badge-warning hitl-badge-spacing">WAITING APPROVAL</span>
                    <h4 class="hitl-item-title">${sess.display_name}</h4>
                    <span class="hitl-item-meta">Source IP: <strong class="text-cyan font-mono">${sess.source_ip || 'N/A'}</strong> | Rule ID: <strong class="font-mono">${sess.siem_rule_id || 'N/A'}</strong></span>
                </div>
                <span class="time hitl-item-time">${dateStr}</span>
            </div>
            
            <div class="hitl-justification-block-hide" id="hitl-justification-${sess.id}">
                Loading explanation…
            </div>

            <div class="hitl-details-container">
                <p class="hitl-details-label">Requested Containment Action:</p>
                <div class="hitl-details-mono-layout">
                    <div><span class="text-amber">ACTION:</span> <span class="text-bright font-bold" id="hitl-tool-${sess.id}">Loading action…</span></div>
                    <div><span class="text-amber">ARGUMENTS:</span></div>
                    <pre class="hitl-details-pre"><code id="hitl-args-${sess.id}">Loading parameters…</code></pre>
                </div>
            </div>
            
            <div class="hitl-footer-layout">
                <button class="btn btn-secondary inspect-session-btn btn-xs-padding-inspect" data-session-id="${sess.id}">
                    <i class="fa-solid fa-magnifying-glass" aria-hidden="true"></i> Inspect Session Logs
                </button>
                <div class="hitl-footer-actions-row">
                    <button class="btn btn-muted quick-reject-btn btn-padding-sm" data-session-id="${sess.id}" ${processingSessions.has(sess.id) ? 'disabled' : ''}>Reject</button>
                    <button class="btn btn-success quick-approve-btn btn-padding-sm" data-session-id="${sess.id}" ${processingSessions.has(sess.id) ? 'disabled' : ''}>
                        ${processingSessions.has(sess.id) ? '<i class="fa-solid fa-spinner fa-spin" aria-hidden="true"></i> Processing…' : 'Approve'}
                    </button>
                </div>
            </div>
        `;
        
        // Fetch event logs to extract the tool arguments requested for this specific session
        fetch(`/web/sessions/${sess.id}/events`)
            .then(res => res.json())
            .then(events => {
                // Find hitl_request event to get the detailed justification
                const hitlRequestEvent = events.slice().reverse().find(e => e.event_type === 'hitl_request');
                // Find last event that represents a think/tool step requesting HITL
                const hitlEvent = events.slice().reverse().find(e => e.event_type === 'think' && e.metadata && e.metadata.tool_name);
                
                const toolEl = card.querySelector(`#hitl-tool-${sess.id}`);
                const argsEl = card.querySelector(`#hitl-args-${sess.id}`);
                const justificationEl = card.querySelector(`#hitl-justification-${sess.id}`);
                
                if (justificationEl) {
                    if (hitlRequestEvent && hitlRequestEvent.content) {
                        justificationEl.innerHTML = formatMarkdownToHtml(hitlRequestEvent.content);
                        justificationEl.style.display = 'block';
                    } else {
                        justificationEl.style.display = 'none';
                    }
                }
                
                let toolName = 'isolate_endpoint';
                let toolArgs = { agent_id: sess.alert_payload?.data?.agent?.id || '1' };
                
                if (hitlRequestEvent && hitlRequestEvent.metadata && hitlRequestEvent.metadata.tool_name) {
                    toolName = hitlRequestEvent.metadata.tool_name;
                    toolArgs = hitlRequestEvent.metadata.tool_args || hitlRequestEvent.metadata.tool_input || {};
                } else if (hitlEvent && hitlEvent.metadata && hitlEvent.metadata.tool_name) {
                    toolName = hitlEvent.metadata.tool_name;
                    toolArgs = hitlEvent.metadata.tool_input || {};
                }
                
                // Human-friendly representation for the pending HITL card
                toolEl.textContent = `${getFriendlyToolName(toolName)} (${toolName})`;
                if (typeof toolArgs === 'object' && FRIENDLY_TOOLS[toolName]) {
                    const lines = [];
                    // Context-based target enrichment for isolate_endpoint
                    if (toolName === 'isolate_endpoint') {
                        const agentName = sess.alert_payload?.all_fields?.agent?.name || sess.alert_payload?.all_fields?.manager?.name || '';
                        const hostname = sess.alert_payload?.all_fields?.predecoder?.hostname || '';
                        const srcIp = sess.alert_payload?.all_fields?.data?.srcip || sess.alert_payload?.all_fields?.syslog_headers?.from || '';
                        
                        if (agentName || hostname) {
                            lines.push(`Target Host: ${agentName || hostname}`);
                        }
                        if (srcIp) {
                            lines.push(`Trigger IP: ${srcIp}`);
                        }
                        // Skip displaying raw agent_id parameter because it's not meaningful in the front-end (we show target hostname instead)
                    } else {
                        Object.keys(toolArgs).forEach(k => {
                            const label = FRIENDLY_TOOLS[toolName].paramLabels[k] || k;
                            lines.push(`${label}: ${toolArgs[k]}`);
                        });
                    }
                    argsEl.textContent = lines.join('\n');
                } else {
                    argsEl.textContent = typeof toolArgs === 'string' 
                        ? toolArgs 
                        : JSON.stringify(toolArgs, null, 2);
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
    if (processingSessions.has(sessionId)) return;
    processingSessions.add(sessionId);

    // Disable all approve/reject buttons for this session in the UI immediately
    const approveButtons = document.querySelectorAll(`.quick-approve-btn[data-session-id="${sessionId}"], #detail-hitl-approve`);
    const rejectButtons = document.querySelectorAll(`.quick-reject-btn[data-session-id="${sessionId}"], #detail-hitl-reject`);
    
    approveButtons.forEach(btn => {
        btn.disabled = true;
        if (action === 'approve') {
            btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin" aria-hidden="true"></i> Processing…';
        }
    });
    rejectButtons.forEach(btn => {
        btn.disabled = true;
        if (action === 'reject') {
            btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin" aria-hidden="true"></i> Processing…';
        }
    });

    try {
        const msg = action === 'approve' ? 'yes' : 'no';
        
        // If the user is actively viewing the session detail page, stream the execution live to the terminal/timeline
        if (panels['session-detail'].classList.contains('active-panel') && activeSessionId === sessionId) {
            if (detailHitlCard) {
                detailHitlCard.classList.add('hide');
            }
            await sendPrompt(msg);
        } else {
            // Otherwise (e.g. from Dashboard or HITL Queue quick action buttons), run in the background using REST API
            const response = await fetch(`/web/sessions/${sessionId}/${action}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
            if (!response.ok) {
                throw new Error(`Failed to submit HITL action: ${response.status}`);
            }
        }
    } catch (err) {
        console.error('Failed to submit HITL action:', err);
    } finally {
        processingSessions.delete(sessionId);
        
        // Reload the active panel
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
        const events = eventsRes.ok ? await eventsRes.json() : [];
        
        renderSessionDetails(sess, events);
    } catch (err) {
        console.error('Failed to open session detail view:', err);
    }
}

function renderSessionDetails(sess, events) {
    // Switch to panel
    switchView('session-detail');
    viewTitle.textContent = "Incident Triage Detail";
    viewDesc.textContent = `Detailed analysis of investigation session ${sess.id.substring(0,8)}…`;
    sessionControls.classList.add('hide');

    // Populate Headers
    detailDisplayName.textContent = sess.display_name;
    detailTimeBadge.textContent = `Created: ${formatDate(sess.created_at)}`;
    
    // Source Badge
    detailSourceBadge.className = sess.source === 'SIEM' ? 'badge badge-error' : 'badge badge-success';
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
    if (sess.source === 'SIEM') {
        detailWazuhCard.classList.remove('hide');
        detailRawAlertCard.classList.remove('hide');
        
        // Fill Wazuh Details
        wazuhRuleId.textContent = sess.siem_rule_id || 'N/A';
        wazuhRuleLevel.textContent = sess.siem_severity || 'N/A';
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
            
            // Look for hitl_request event to get the detailed justification/message
            const hitlRequestEvent = events.slice().reverse().find(e => e.event_type === 'hitl_request');
            const hitlEvent = events.slice().reverse().find(e => e.event_type === 'think' && e.metadata && e.metadata.tool_name);
            
            if (detailHitlJustification) {
                if (hitlRequestEvent && hitlRequestEvent.content) {
                    detailHitlJustification.innerHTML = formatMarkdownToHtml(hitlRequestEvent.content);
                    detailHitlJustification.style.display = 'block';
                } else {
                    detailHitlJustification.textContent = 'Awaiting human authorization for the response action.';
                    detailHitlJustification.style.display = 'block';
                }
            }
            
            let toolName = 'isolate_endpoint';
            let toolArgs = { agent_id: sess.alert_payload?.data?.agent?.id || '1' };
            
            if (hitlRequestEvent && hitlRequestEvent.metadata && hitlRequestEvent.metadata.tool_name) {
                toolName = hitlRequestEvent.metadata.tool_name;
                toolArgs = hitlRequestEvent.metadata.tool_args || hitlRequestEvent.metadata.tool_input || {};
            } else if (hitlEvent && hitlEvent.metadata && hitlEvent.metadata.tool_name) {
                toolName = hitlEvent.metadata.tool_name;
                toolArgs = hitlEvent.metadata.tool_input || {};
            }
            
            // Build human-friendly action summary representation
            const friendlyName = getFriendlyToolName(toolName);
            const detailHitlActionFriendly = document.getElementById('detail-hitl-action-friendly');
            const detailHitlParamsList = document.getElementById('detail-hitl-params-list');
            
            if (detailHitlActionFriendly) {
                detailHitlActionFriendly.textContent = friendlyName;
            }
            if (detailHitlParamsList) {
                detailHitlParamsList.innerHTML = renderFriendlyParams(toolName, toolArgs, sess.alert_payload);
            }
            
            detailHitlTool.textContent = toolName;
            detailHitlArgs.textContent = typeof toolArgs === 'string' 
                ? toolArgs 
                : JSON.stringify(toolArgs, null, 2);
            
            // Reset button states in case they were previously disabled/spinning
            detailHitlApprove.disabled = false;
            detailHitlApprove.innerHTML = 'Approve';
            detailHitlReject.disabled = false;
            detailHitlReject.innerHTML = 'Reject';

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
                stepBlock.classList.add('step-thinking');
                headerHtml = `<div class="step-type-header step-thinking"><i class="fa-solid fa-brain"></i> THINKING (${step.actor})</div>`;
                contentHtml = `<div class="step-content text-cyan">${step.content}</div>`;
                break;
                
            case 'tool':
            case 'act':
                stepBlock.classList.add('step-tool');
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
                stepBlock.classList.add('step-observation');
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
                    stepBlock.classList.add('step-answer');
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
        const res = await fetch(`/web/sessions/${sessionId}/workspace`);
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
                        openSessionDetail(activeSessionId);
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
        openSessionDetail(activeSessionId);
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
        const response = await fetch('/web/sessions', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json'
            }
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
            <i class="fa-solid fa-spinner fa-spin text-cyan" aria-hidden="true"></i> Loading registered agent personas…
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
            <i class="fa-solid fa-spinner fa-spin text-cyan" aria-hidden="true"></i> Loading…
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

function formatMarkdownToHtml(markdown) {
    if (!markdown) return '';
    let html = markdown;
    
    // Replace bold text: **text** -> <strong>text</strong>
    html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    
    // Replace bullet points: - item -> <li>item</li> (wrapped in ul)
    const lines = html.split('\n');
    let inList = false;
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (line.startsWith('- ') || line.startsWith('* ')) {
            const content = line.substring(2);
            lines[i] = (inList ? '' : '<ul style="margin: 4px 0 8px 16px; padding: 0; list-style-type: disc;">') + `<li style="margin-bottom: 2px;">${content}</li>`;
            inList = true;
        } else {
            if (inList) {
                lines[i] = '</ul>' + lines[i];
                inList = false;
            }
        }
    }
    if (inList) {
        lines[lines.length - 1] = lines[lines.length - 1] + '</ul>';
    }
    
    // Join lines with <br> for non-list elements
    html = lines.join('\n');
    html = html.replace(/\n/g, '<br>');
    
    // Clean up double <br> around lists
    html = html.replace(/<\/ul><br>/g, '</ul>');
    html = html.replace(/<br><ul/g, '<ul');
    
    return html;
}

// Senior UI Floating Toast System
function showNotification(message, type = 'success') {
    let container = document.getElementById('notification-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'notification-container';
        container.style.position = 'fixed';
        container.style.bottom = '24px';
        container.style.right = '24px';
        container.style.zIndex = '9999';
        container.style.display = 'flex';
        container.style.flexDirection = 'column';
        container.style.gap = '12px';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = 'glass-panel';
    toast.style.display = 'flex';
    toast.style.alignItems = 'center';
    toast.style.gap = '12px';
    toast.style.padding = '14px 20px';
    toast.style.borderRadius = '8px';
    toast.style.minWidth = '280px';
    toast.style.maxWidth = '400px';
    toast.style.boxShadow = '0 8px 32px 0 rgba(0, 0, 0, 0.4)';
    toast.style.animation = 'slideIn 0.3s ease-out, fadeOut 0.5s ease-in 3.5s forwards';

    let icon = '<i class="fa-solid fa-circle-check" style="color: var(--primary);"></i>';
    let borderColor = 'rgba(6, 182, 212, 0.3)';
    let bgColor = 'rgba(6, 182, 212, 0.1)';

    if (type === 'error') {
        icon = '<i class="fa-solid fa-circle-xmark" style="color: #ef4444;"></i>';
        borderColor = 'rgba(239, 68, 68, 0.3)';
        bgColor = 'rgba(239, 68, 68, 0.1)';
    } else if (type === 'warning') {
        icon = '<i class="fa-solid fa-triangle-exclamation" style="color: #f59e0b;"></i>';
        borderColor = 'rgba(245, 158, 11, 0.3)';
        bgColor = 'rgba(245, 158, 11, 0.1)';
    }

    toast.style.border = `1px solid ${borderColor}`;
    toast.style.backgroundColor = bgColor;
    toast.style.color = '#fff';
    toast.style.fontSize = '13.5px';
    toast.style.fontWeight = '500';

    toast.innerHTML = `
        ${icon}
        <span style="flex-grow: 1;">${message}</span>
    `;

    container.appendChild(toast);

    setTimeout(() => {
        toast.remove();
        if (container.children.length === 0) {
            container.remove();
        }
    }, 4000);
}

// Senior UI Asynchronous Loader & Concurrency Lock
async function fetchWithLoader(loaderOptions, fetchFn) {
    const { buttons, container } = loaderOptions;

    // Disable controls to prevent double clicks / race conditions
    if (buttons) {
        buttons.forEach(btn => { if (btn) btn.disabled = true; });
    }
    
    // Set visual loading fade
    if (container) {
        container.classList.add('loading-fade');
    }

    try {
        await fetchFn();
    } catch (err) {
        console.error('Data load error:', err);
        showNotification(err.message || 'Connection lost. Failed to retrieve dataset.', 'error');
    } finally {
        // Restore opacity and events
        if (container) {
            container.classList.remove('loading-fade');
        }
        if (buttons) {
            // Re-enable limit selectors or refresh buttons specifically;
            // prev/next are handled by their render functions.
            buttons.forEach(btn => {
                if (btn && (btn.tagName === 'SELECT' || btn.id.includes('refresh') || btn.id === 'logout-btn')) {
                    btn.disabled = false;
                }
            });
        }
    }
}

// ==========================================
// HITL PRESENTATION HELPERS
// ==========================================
const FRIENDLY_TOOLS = {
    'isolate_endpoint': {
        title: 'Isolate Endpoint / Host',
        paramLabels: {
            'agent_id': 'Wazuh Agent ID'
        }
    },
    'block_ip': {
        title: 'Block IP Address',
        paramLabels: {
            'ip_address': 'IP Address',
            'ip': 'IP Address',
            'direction': 'Direction'
        }
    },
    'disable_user_account': {
        title: 'Disable User Account',
        paramLabels: {
            'username': 'Username',
            'user': 'Username',
            'domain': 'Domain'
        }
    },
    'delete_file': {
        title: 'Delete File',
        paramLabels: {
            'path': 'File Path',
            'filepath': 'File Path'
        }
    },
    'execute_command': {
        title: 'Execute Command',
        paramLabels: {
            'cmd': 'Command',
            'command': 'Command'
        }
    }
};

function getFriendlyToolName(toolName) {
    return FRIENDLY_TOOLS[toolName]?.title || toolName;
}

function renderFriendlyParams(toolName, toolArgs, alertPayload) {
    if (!toolArgs || typeof toolArgs !== 'object') {
        return `<div class="param-item"><span class="param-label">Arguments:</span> <span class="param-value">${toolArgs}</span></div>`;
    }
    const toolConfig = FRIENDLY_TOOLS[toolName];
    const keys = Object.keys(toolArgs);
    
    let html = '';
    
    // Context enrichment from alert payload for isolate_endpoint
    if (toolName === 'isolate_endpoint') {
        const agentName = alertPayload?.all_fields?.agent?.name || alertPayload?.all_fields?.manager?.name || '';
        const hostname = alertPayload?.all_fields?.predecoder?.hostname || '';
        const srcIp = alertPayload?.all_fields?.data?.srcip || alertPayload?.all_fields?.syslog_headers?.from || '';
        
        if (agentName || hostname) {
            html += `
                <div class="param-item" style="display: flex; justify-content: space-between; font-size: 12.5px; margin-bottom: 6px; border-bottom: 1px dashed rgba(245, 158, 11, 0.1); padding-bottom: 4px;">
                    <span class="param-label" style="color: var(--text-muted);"><i class="fa-solid fa-server"></i> Target Hostname/Name:</span>
                    <strong class="param-value" style="color: var(--warning); font-family: var(--font-mono);">${agentName || hostname}</strong>
                </div>
            `;
        }
        if (srcIp) {
            html += `
                <div class="param-item" style="display: flex; justify-content: space-between; font-size: 12.5px; margin-bottom: 6px; border-bottom: 1px dashed rgba(245, 158, 11, 0.1); padding-bottom: 4px;">
                    <span class="param-label" style="color: var(--text-muted);"><i class="fa-solid fa-network-wired"></i> Origin/Triggering IP:</span>
                    <strong class="param-value" style="color: var(--text-bright); font-family: var(--font-mono);">${srcIp}</strong>
                </div>
            `;
        }
        // Completely skip showing agent_id raw parameter since it's represented by hostname above
        return html;
    }
    
    if (keys.length > 0) {
        html += keys.map(key => {
            const label = toolConfig?.paramLabels[key] || key;
            const val = toolArgs[key];
            return `
                <div class="param-item" style="display: flex; justify-content: space-between; font-size: 12.5px; margin-bottom: 4px;">
                    <span class="param-label" style="color: var(--text-muted);">${label}:</span>
                    <strong class="param-value" style="font-family: var(--font-mono); color: var(--warning);">${val}</strong>
                </div>
            `;
        }).join('');
    } else {
        html += `<div class="param-item"><span class="param-label">Parameters:</span> <span class="param-value">None</span></div>`;
    }
    
    return html;
}

