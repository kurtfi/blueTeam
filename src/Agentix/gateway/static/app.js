/**
 * Agentix Web UI - Bootstrap & Main Application Controller
 */

import { store } from './state.js';
import * as api from './api.js';
import { switchView } from './router.js';
import { openSessionDetail, submitHitlAction } from './chat.js';
import { loadPlaybooks, showPlaybookDetails } from './playbooks.js';
import { 
    escapeHtml, 
    formatDate, 
    debounce, 
    formatMarkdownToHtml, 
    showNotification, 
    fetchWithLoader 
} from './utils.js';

// DOM Elements
const loginContainer = document.getElementById('login-container');
const appContainer = document.getElementById('app-container');
const loginForm = document.getElementById('login-form');
const loginError = document.getElementById('login-error');
const errorText = document.getElementById('error-text');

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

const agentsCardsContainer = document.getElementById('agents-cards-container');
const playbooksListContainer = document.getElementById('playbooks-list-container');
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

// Detail page buttons
const detailBackBtn = document.getElementById('detail-back-btn');
const detailRefreshBtn = document.getElementById('detail-refresh-btn');
const rawAlertToggleHeader = document.getElementById('raw-alert-toggle-header');

// Start initialization
document.addEventListener('DOMContentLoaded', () => {
    checkAuth();
    setupEventListeners();
    
    // Listen for custom events published by other modules
    document.addEventListener('hitl-action-complete', (e) => {
        const view = store.getState().activeView;
        if (view === 'dashboard') {
            loadDashboardData();
        } else if (view === 'sessions') {
            loadSessionsList(false);
        } else if (view === 'session-detail') {
            const activeSessionId = store.getState().activeSessionId;
            if (activeSessionId) {
                openSessionDetail(activeSessionId);
            }
        } else if (view === 'hitl') {
            loadHitlQueue(false);
        }
    });
});

// 1. Authentication Handlers
async function checkAuth() {
    try {
        const userData = await api.getMe();
        showApp(userData);
    } catch (error) {
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
            await api.login(usernameInput, passwordInput);
            await checkAuth();
        } catch (error) {
            showLoginError(error.message || 'Authentication failed. Please check credentials.');
            submitBtn.disabled = false;
            submitBtn.innerHTML = originalBtnHtml;
        }
    });

    // Logout click
    logoutBtn.addEventListener('click', async () => {
        try {
            await api.logout();
            store.setState({ activeSessionId: null });
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
            const state = store.getState();
            if (state.activeSessionId) {
                await fetchWithLoader(
                    { buttons: [detailRefreshBtn], container: document.getElementById('detail-timeline') },
                    async () => {
                        await openSessionDetail(state.activeSessionId);
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
            const state = store.getState();
            if (state.dashboardPage > 1) {
                await fetchWithLoader(
                    { buttons: [dashboardPrevBtn, dashboardNextBtn, dashboardLimitSelect], container: dashboardRecentList },
                    async () => {
                        store.setState({ dashboardPage: state.dashboardPage - 1 });
                        await loadDashboardSessions();
                    }
                );
            }
        });
    }
    if (dashboardNextBtn) {
        dashboardNextBtn.addEventListener('click', async () => {
            const state = store.getState();
            const maxPage = Math.ceil(state.dashboardTotalCount / state.dashboardPageSize) || 1;
            if (state.dashboardPage < maxPage) {
                await fetchWithLoader(
                    { buttons: [dashboardPrevBtn, dashboardNextBtn, dashboardLimitSelect], container: dashboardRecentList },
                    async () => {
                        store.setState({ dashboardPage: state.dashboardPage + 1 });
                        await loadDashboardSessions();
                    }
                );
            }
        });
    }

    if (sessionsPrevBtn) {
        sessionsPrevBtn.addEventListener('click', async () => {
            const state = store.getState();
            if (state.sessionsPage > 1) {
                await fetchWithLoader(
                    { buttons: [sessionsPrevBtn, sessionsNextBtn, sessionsLimitSelect], container: sessionsListContainer },
                    async () => {
                        store.setState({ sessionsPage: state.sessionsPage - 1 });
                        await loadSessionsList(false);
                    }
                );
            }
        });
    }
    if (sessionsNextBtn) {
        sessionsNextBtn.addEventListener('click', async () => {
            const state = store.getState();
            const maxPage = Math.ceil(state.sessionsTotalCount / state.sessionsPageSize) || 1;
            if (state.sessionsPage < maxPage) {
                await fetchWithLoader(
                    { buttons: [sessionsPrevBtn, sessionsNextBtn, sessionsLimitSelect], container: sessionsListContainer },
                    async () => {
                        store.setState({ sessionsPage: state.sessionsPage + 1 });
                        await loadSessionsList(false);
                    }
                );
            }
        });
    }

    if (hitlPrevBtn) {
        hitlPrevBtn.addEventListener('click', async () => {
            const state = store.getState();
            if (state.hitlPage > 1) {
                await fetchWithLoader(
                    { buttons: [hitlPrevBtn, hitlNextBtn, hitlLimitSelect], container: hitlListContainer },
                    async () => {
                        store.setState({ hitlPage: state.hitlPage - 1 });
                        await loadHitlQueue(false);
                    }
                );
            }
        });
    }
    if (hitlNextBtn) {
        hitlNextBtn.addEventListener('click', async () => {
            const state = store.getState();
            const maxPage = Math.ceil(state.hitlTotalCount / state.hitlPageSize) || 1;
            if (state.hitlPage < maxPage) {
                await fetchWithLoader(
                    { buttons: [hitlPrevBtn, hitlNextBtn, hitlLimitSelect], container: hitlListContainer },
                    async () => {
                        store.setState({ hitlPage: state.hitlPage + 1 });
                        await loadHitlQueue(false);
                    }
                );
            }
        });
    }

    // Limit selectors
    if (dashboardLimitSelect) {
        dashboardLimitSelect.addEventListener('change', async (e) => {
            await fetchWithLoader(
                { buttons: [dashboardPrevBtn, dashboardNextBtn, dashboardLimitSelect], container: dashboardRecentList },
                async () => {
                    store.setState({ 
                        dashboardPageSize: parseInt(e.target.value),
                        dashboardPage: 1
                    });
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
                    store.setState({ 
                        sessionsPageSize: parseInt(e.target.value),
                        sessionsPage: 1
                    });
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
                    store.setState({ 
                        hitlPageSize: parseInt(e.target.value),
                        hitlPage: 1
                    });
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
            store.setState({ activeAgent: agentId });
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

// 4. Data Loading - Dashboard View
async function loadDashboardData() {
    try {
        const stats = await api.getSessionStats();
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
            
        updateHitlBadge(stats.pending_hitl);
        
        const data = await api.getSessions({ limit: 100, offset: 0 });
        const dropdownList = data.sessions || [];
        const activeOnly = dropdownList.filter(sess => sess.status === 'ACTIVE' || sess.status === 'WAITING_APPROVAL');
        updateHeaderDropdown(activeOnly);

        store.setState({ dashboardPage: 1 });
        await loadDashboardSessions();
    } catch (err) {
        console.error('Failed to load dashboard data:', err);
    }
}

async function loadDashboardSessions() {
    const state = store.getState();
    try {
        const offset = (state.dashboardPage - 1) * state.dashboardPageSize;
        const data = await api.getSessions({ limit: state.dashboardPageSize, offset });
        
        store.setState({
            dashboardTotalCount: data.total_count,
            dashboardSessionsList: data.sessions || []
        });
        renderRecentSessionsPage();
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
    
    const state = store.getState();
    const sessionsList = state.dashboardSessionsList;
    
    if (!sessionsList || sessionsList.length === 0) {
        dashboardRecentList.innerHTML = `<div class="tree-empty">No sessions created yet. Start a new chat or trigger a SIEM alert.</div>`;
        if (dashboardPageInfo) dashboardPageInfo.textContent = "Showing 0–0 of 0";
        if (dashboardPrevBtn) dashboardPrevBtn.disabled = true;
        if (dashboardNextBtn) dashboardNextBtn.disabled = true;
        return;
    }
    
    const maxPage = Math.ceil(state.dashboardTotalCount / state.dashboardPageSize) || 1;
    let page = state.dashboardPage;
    if (page > maxPage) {
        page = maxPage;
        store.setState({ dashboardPage: maxPage });
    }
    
    if (dashboardPageInfo) {
        const startItem = state.dashboardTotalCount === 0 ? 0 : (page - 1) * state.dashboardPageSize + 1;
        const endItem = Math.min(page * state.dashboardPageSize, state.dashboardTotalCount);
        dashboardPageInfo.textContent = `Showing ${startItem}–${endItem} of ${state.dashboardTotalCount}`;
    }
    if (dashboardPrevBtn) dashboardPrevBtn.disabled = page === 1;
    if (dashboardNextBtn) dashboardNextBtn.disabled = page === maxPage;
    
    dashboardRecentList.innerHTML = '';
    sessionsList.forEach(sess => {
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
            : sess.status === 'FAILED'
            ? `<span class="badge badge-error">FAILED</span>`
            : `<span class="badge badge-info">ACTIVE</span>`;
            
        const verdictBadge = sess.verdict && sess.verdict !== 'UNDETERMINED'
            ? `<span class="badge badge-info recent-verdict-badge">${escapeHtml(sess.verdict)}</span>`
            : '';
            
        item.innerHTML = `
            <div class="alert-meta alert-meta-container">
                <div class="badge-container-row">
                    ${sourceBadge}
                    ${statusBadge}
                    ${verdictBadge}
                </div>
                <span class="time">${formatDate(sess.created_at)}</span>
            </div>
            <h4 class="recent-title">${escapeHtml(sess.display_name)}</h4>
            <div class="recent-info-row">
                <span>Agent: <strong class="text-cyan font-mono">${escapeHtml(sess.agent_name || 'N/A')}</strong></span>
                <span>Tools Executed: <strong>${escapeHtml(sess.tool_calls || 0)}</strong></span>
            </div>
            <div class="recent-action-row">
                <button class="btn btn-secondary review-session-btn btn-xs-padding-review" data-session-id="${sess.id}">
                    <span>Review Session</span>
                    <i class="fa-solid fa-arrow-right icon-arrow-xs" aria-hidden="true"></i>
                </button>
            </div>
        `;
        
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
        if (sess.id === store.getState().activeSessionId) opt.selected = true;
        sessionSelect.appendChild(opt);
    });
}

// 5. Data Loading - Sessions List View
async function loadSessionsList(resetPage = true) {
    try {
        if (resetPage) {
            store.setState({ sessionsPage: 1 });
        }
        const state = store.getState();
        const srcVal = filterSource.value;
        const statusVal = filterStatus.value;
        const searchVal = sessionsSearch.value.trim();
        
        const offset = (state.sessionsPage - 1) * state.sessionsPageSize;
        const data = await api.getSessions({
            limit: state.sessionsPageSize,
            offset,
            source: srcVal,
            status: statusVal,
            search: searchVal
        });

        store.setState({
            sessionsTotalCount: data.total_count,
            sessionsFullList: data.sessions || []
        });
        renderSessionsListPage();
    } catch (err) {
        console.error('Failed to load sessions list:', err);
    }
}

function renderSessionsListPage() {
    if (!sessionsListContainer) return;
    
    const state = store.getState();
    const sessionsList = state.sessionsFullList;
    
    if (!sessionsList || sessionsList.length === 0) {
        sessionsListContainer.innerHTML = `<div class="tree-empty">No sessions matching the filters found.</div>`;
        if (sessionsPageInfo) sessionsPageInfo.textContent = "Showing 0–0 of 0";
        if (sessionsPrevBtn) sessionsPrevBtn.disabled = true;
        if (sessionsNextBtn) sessionsNextBtn.disabled = true;
        return;
    }
    
    const maxPage = Math.ceil(state.sessionsTotalCount / state.sessionsPageSize) || 1;
    let page = state.sessionsPage;
    if (page > maxPage) {
        page = maxPage;
        store.setState({ sessionsPage: maxPage });
    }
    
    if (sessionsPageInfo) {
        const startItem = state.sessionsTotalCount === 0 ? 0 : (page - 1) * state.sessionsPageSize + 1;
        const endItem = Math.min(page * state.sessionsPageSize, state.sessionsTotalCount);
        sessionsPageInfo.textContent = `Showing ${startItem}–${endItem} of ${state.sessionsTotalCount}`;
    }
    if (sessionsPrevBtn) sessionsPrevBtn.disabled = page === 1;
    if (sessionsNextBtn) sessionsNextBtn.disabled = page === maxPage;
    
    sessionsListContainer.innerHTML = '';
    sessionsList.forEach(sess => {
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
            : sess.status === 'FAILED'
            ? `<span class="badge badge-error">FAILED</span>`
            : `<span class="badge badge-info">ACTIVE</span>`;
            
        const verdictBadge = sess.verdict && sess.verdict !== 'UNDETERMINED'
            ? `<span class="badge badge-info session-item-date">${escapeHtml(sess.verdict)}</span>`
            : '';
            
        card.innerHTML = `
            <div class="session-item-layout">
                <div class="session-item-content-wrapper">
                    <div class="alert-meta session-item-meta">
                        ${sourceBadge}
                        ${statusBadge}
                        ${verdictBadge}
                        <span class="time session-item-date">${formatDate(sess.created_at)}</span>
                    </div>
                    <h4 class="session-item-title">${escapeHtml(sess.display_name)}</h4>
                    <div class="session-item-details-row">
                        <span>Agent: <strong class="text-cyan font-mono">${escapeHtml(sess.agent_name || 'N/A')}</strong></span>
                        <span>Messages: <strong>${escapeHtml(sess.message_count || 0)}</strong></span>
                        <span>Tool Calls: <strong>${escapeHtml(sess.tool_calls || 0)}</strong></span>
                        <span>HITL Approvals: <strong>${escapeHtml(sess.hitl_count || 0)}</strong></span>
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
            store.setState({ hitlPage: 1 });
        }
        const state = store.getState();
        const offset = (state.hitlPage - 1) * state.hitlPageSize;
        const data = await api.getSessions({
            limit: state.hitlPageSize,
            offset,
            status: 'WAITING_APPROVAL'
        });

        store.setState({
            hitlTotalCount: data.total_count,
            hitlFullList: data.sessions || []
        });
        renderHitlQueuePage();
        updateHitlBadge(data.total_count);
    } catch (err) {
        console.error('Failed to load HITL queue:', err);
    }
}

function renderHitlQueuePage() {
    if (!hitlListContainer) return;
    
    const state = store.getState();
    const hitlList = state.hitlFullList;
    
    if (!hitlList || hitlList.length === 0) {
        hitlListContainer.innerHTML = `<div class="tree-empty">No pending actions awaiting approval. Active alerts are fully automated.</div>`;
        if (hitlPageInfo) hitlPageInfo.textContent = "Showing 0–0 of 0";
        if (hitlPrevBtn) hitlPrevBtn.disabled = true;
        if (hitlNextBtn) hitlNextBtn.disabled = true;
        return;
    }
    
    const maxPage = Math.ceil(state.hitlTotalCount / state.hitlPageSize) || 1;
    let page = state.hitlPage;
    if (page > maxPage) {
        page = maxPage;
        store.setState({ hitlPage: maxPage });
    }
    
    if (hitlPageInfo) {
        const startItem = state.hitlTotalCount === 0 ? 0 : (page - 1) * state.hitlPageSize + 1;
        const endItem = Math.min(page * state.hitlPageSize, state.hitlTotalCount);
        hitlPageInfo.textContent = `Showing ${startItem}–${endItem} of ${state.hitlTotalCount}`;
    }
    if (hitlPrevBtn) hitlPrevBtn.disabled = page === 1;
    if (hitlNextBtn) hitlNextBtn.disabled = page === maxPage;
    
    hitlListContainer.innerHTML = '';
    hitlList.forEach(sess => {
        const card = document.createElement('div');
        card.className = 'glass-panel hitl-warning-card';
        
        card.innerHTML = `
            <div class="hitl-item-header">
                <div>
                    <span class="badge badge-warning hitl-badge-spacing">WAITING APPROVAL</span>
                    <h4 class="hitl-item-title">${escapeHtml(sess.display_name)}</h4>
                    <span class="hitl-item-meta">Source IP: <strong class="text-cyan font-mono">${escapeHtml(sess.source_ip || 'N/A')}</strong> | Rule ID: <strong class="font-mono">${escapeHtml(sess.siem_rule_id || 'N/A')}</strong></span>
                </div>
                <span class="time hitl-item-time">${formatDate(sess.created_at)}</span>
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
                    <button class="btn btn-muted quick-reject-btn btn-padding-sm" data-session-id="${sess.id}" ${state.processingSessions.has(sess.id) ? 'disabled' : ''}>Reject</button>
                    <button class="btn btn-success quick-approve-btn btn-padding-sm" data-session-id="${sess.id}" ${state.processingSessions.has(sess.id) ? 'disabled' : ''}>
                        ${state.processingSessions.has(sess.id) ? '<i class="fa-solid fa-spinner fa-spin" aria-hidden="true"></i> Processing…' : 'Approve'}
                    </button>
                </div>
            </div>
        `;
        
        // Fetch event logs to extract the tool arguments requested for this specific session
        api.getSessionEvents(sess.id)
            .then(events => {
                const hitlRequestEvent = events.slice().reverse().find(e => e.event_type === 'hitl_request');
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
                
                toolEl.textContent = `${getFriendlyToolName(toolName)} (${toolName})`;
                if (typeof toolArgs === 'object' && api.FRIENDLY_TOOLS) {
                    // Fallback to friendlier representations if available
                    // We also import FRIENDLY_TOOLS config locally or from utils
                }
                
                // Represent arguments in block
                if (toolName === 'isolate_endpoint') {
                    const agentName = sess.alert_payload?.all_fields?.agent?.name || sess.alert_payload?.all_fields?.manager?.name || '';
                    const hostname = sess.alert_payload?.all_fields?.predecoder?.hostname || '';
                    const srcIp = sess.alert_payload?.all_fields?.data?.srcip || sess.alert_payload?.all_fields?.syslog_headers?.from || '';
                    
                    const lines = [];
                    if (agentName || hostname) lines.push(`Target Host: ${agentName || hostname}`);
                    if (srcIp) lines.push(`Trigger IP: ${srcIp}`);
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

// 7. Personas Tab Handlers
async function loadAgents() {
    if (!agentsCardsContainer) return;
    
    agentsCardsContainer.innerHTML = `
        <div class="loading-state">
            <i class="fa-solid fa-spinner fa-spin text-cyan" aria-hidden="true"></i> Loading registered agent personas…
        </div>
    `;

    try {
        const agents = await api.getAgents();
        renderAgents(agents);
    } catch (err) {
        console.error("Failed to load agents", err);
        agentsCardsContainer.innerHTML = `
            <div class="error-msg">
                <i class="fa-solid fa-triangle-exclamation"></i>
                <span>Failed to load agent personas: ${escapeHtml(err.message)}</span>
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

    const state = store.getState();

    agentsCardsContainer.innerHTML = '';
    agents.forEach(agent => {
        const isActive = agent.id === state.activeAgent;
        const card = document.createElement('div');
        card.className = `agent-card glass-panel ${isActive ? 'active-agent-card' : ''}`;
        
        const toolChips = agent.tools && agent.tools.length > 0
            ? agent.tools.map(t => `<span class="tool-chip"><i class="fa-solid fa-square-poll-horizontal"></i> ${escapeHtml(t)}</span>`).join('')
            : '<span class="tool-chip text-muted">None</span>';

        card.innerHTML = `
            <div class="agent-card-header">
                <div class="agent-avatar">
                    <i class="fa-solid fa-robot"></i>
                </div>
                <div class="agent-meta">
                    <h4>${escapeHtml(agent.name || agent.id)}</h4>
                    <span class="agent-id font-mono">${escapeHtml(agent.id)}</span>
                </div>
                ${isActive ? '<span class="badge badge-success">ACTIVE</span>' : ''}
            </div>
            <p class="agent-desc">${escapeHtml(agent.role || 'No description provided.')}</p>
            <div class="agent-specs">
                <div class="spec-item">
                    <span class="label">MODEL:</span>
                    <span class="val font-mono">${escapeHtml(agent.model || 'unknown')}</span>
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
                    : `<button class="btn btn-primary btn-block activate-agent-btn" data-agent-id="${escapeHtml(agent.id)}">ACTIVATE PERSONA</button>`
                }
            </div>
        `;
        agentsCardsContainer.appendChild(card);
    });
}

// 8. Settings Form Loader
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

// 9. Session Management (Create USER Session)
async function createNewSession() {
    try {
        const data = await api.createSession();
        openSessionDetail(data.session_id);
    } catch (err) {
        console.error('Failed to create user session:', err);
    }
}

// 10. Polling and Utility Helpers
let pollingIntervalId = null;

function startPeriodicPolling() {
    if (pollingIntervalId) {
        clearInterval(pollingIntervalId);
    }
    
    const runPoll = () => {
        if (document.visibilityState !== 'visible') {
            return; // Pause polling when tab is hidden/inactive
        }
        
        const state = store.getState();
        if (state.activeView === 'dashboard') {
            loadDashboardData();
        } else if (state.activeView === 'hitl') {
            loadHitlQueue(false);
        }
    };
    
    pollingIntervalId = setInterval(runPoll, 10000);
    
    // Resume polling immediately when document becomes visible
    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible') {
            runPoll();
        }
    });
}

// Subscribe to state view changes to trigger loading
store.subscribe((state, prevState) => {
    if (state.activeView !== prevState.activeView) {
        const viewName = state.activeView;
        if (viewName === 'dashboard') {
            loadDashboardData();
        } else if (viewName === 'sessions') {
            loadSessionsList(true);
        } else if (viewName === 'hitl') {
            loadHitlQueue(true);
        } else if (viewName === 'personas') {
            loadAgents();
        } else if (viewName === 'playbooks') {
            loadPlaybooks();
        } else if (viewName === 'settings') {
            loadSettingsForm();
        }
    }
});
