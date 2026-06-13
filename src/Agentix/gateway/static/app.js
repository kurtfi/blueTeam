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
    simulations: document.getElementById('nav-simulations'),
    'bulk-evals': document.getElementById('nav-bulk-evals'),
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

    // Simulations Rate Control & Triggers
    const simRateMinus = document.getElementById('sim-rate-minus');
    const simRatePlus = document.getElementById('sim-rate-plus');
    const simRateInput = document.getElementById('sim-rate-input');
    const simTriggerBtn = document.getElementById('sim-trigger-btn');
    const simRunsRefreshBtn = document.getElementById('sim-runs-refresh-btn');
    const simClearSelectionBtn = document.getElementById('sim-clear-selection-btn');

    if (simRateMinus && simRateInput) {
        simRateMinus.addEventListener('click', () => {
            let val = parseFloat(simRateInput.value);
            if (val > 0.2) {
                val = parseFloat((val - 0.5).toFixed(1));
                if (val < 0.1) val = 0.1;
                simRateInput.value = val;
            }
        });
    }
    if (simRatePlus && simRateInput) {
        simRatePlus.addEventListener('click', () => {
            let val = parseFloat(simRateInput.value);
            if (val < 10.0) {
                val = parseFloat((val + 0.5).toFixed(1));
                simRateInput.value = val;
            }
        });
    }

    if (simClearSelectionBtn) {
        simClearSelectionBtn.addEventListener('click', () => {
            selectedScenarioIds.clear();
            document.querySelectorAll('.sc-select-checkbox').forEach(cb => cb.checked = false);
            updateBatchControllerUI();
        });
    }

    if (simTriggerBtn) {
        simTriggerBtn.addEventListener('click', async () => {
            if (selectedScenarioIds.size === 0) return;
            const rate = parseFloat(simRateInput.value) || 1.0;
            const stripLabelsCheckbox = document.getElementById('sim-strip-labels');
            const stripLabels = stripLabelsCheckbox ? stripLabelsCheckbox.checked : false;

            simTriggerBtn.disabled = true;
            const triggerBtnText = document.getElementById('sim-trigger-btn-text');
            const originalText = triggerBtnText ? triggerBtnText.textContent : 'TRIGGER BATCH RUN (0)';
            if (triggerBtnText) {
                triggerBtnText.textContent = 'TRIGGERING BATCH...';
            }

            try {
                const scenarioIds = [...selectedScenarioIds];
                showNotification(`Triggering batch simulation run for ${scenarioIds.length} scenarios...`, 'info');
                
                // Activating and running each scenario sequentially because of database uniqueness constraint
                for (const scId of scenarioIds) {
                    await api.activateSimScenario(scId);
                    await api.runSimScenario(scId, rate, stripLabels);
                }
                
                showNotification(`Successfully triggered ${scenarioIds.length} simulation runs.`, 'success');
                selectedScenarioIds.clear();
                document.querySelectorAll('.sc-select-checkbox').forEach(cb => cb.checked = false);
                updateBatchControllerUI();
                await loadSimulationsData();
            } catch (err) {
                showNotification(err.message || 'Failed to trigger batch simulation', 'error');
            } finally {
                simTriggerBtn.disabled = false;
                updateBatchControllerUI();
            }
        });
    }

    // Details Modal Handlers
    const simModal = document.getElementById('sim-scenario-modal');
    const simModalClose = document.getElementById('sim-modal-close');
    const simModalCloseFooter = document.getElementById('sim-modal-close-footer');
    const simModalRunBtn = document.getElementById('sim-modal-run-btn');

    if (simModalClose) {
        simModalClose.addEventListener('click', () => {
            simModal.classList.add('hide');
        });
    }
    if (simModalCloseFooter) {
        simModalCloseFooter.addEventListener('click', () => {
            simModal.classList.add('hide');
        });
    }
    if (simModal) {
        simModal.addEventListener('click', (e) => {
            if (e.target === simModal) {
                simModal.classList.add('hide');
            }
        });
    }

    const simJsonModal = document.getElementById('sim-json-modal');
    const simJsonModalClose = document.getElementById('sim-json-modal-close');
    const simJsonModalCloseFooter = document.getElementById('sim-json-modal-close-footer');
    const simJsonCopyBtn = document.getElementById('sim-json-copy-btn');

    if (simJsonModalClose) {
        simJsonModalClose.addEventListener('click', () => {
            simJsonModal.classList.add('hide');
        });
    }
    if (simJsonModalCloseFooter) {
        simJsonModalCloseFooter.addEventListener('click', () => {
            simJsonModal.classList.add('hide');
        });
    }
    if (simJsonModal) {
        simJsonModal.addEventListener('click', (e) => {
            if (e.target === simJsonModal) {
                simJsonModal.classList.add('hide');
            }
        });
    }
    if (simJsonCopyBtn) {
        simJsonCopyBtn.addEventListener('click', () => {
            const code = document.getElementById('sim-json-code-block').textContent;
            navigator.clipboard.writeText(code).then(() => {
                showNotification('JSON payload copied to clipboard!', 'success');
            }).catch(err => {
                console.error('Failed to copy text:', err);
            });
        });
    }
    if (simModalRunBtn) {
        simModalRunBtn.addEventListener('click', async () => {
            const scenarioId = simModalRunBtn.getAttribute('data-scenario-id');
            const scenarioName = simModalRunBtn.getAttribute('data-scenario-name');
            const rate = parseFloat(simRateInput.value) || 1.0;
            const stripLabelsCheckbox = document.getElementById('sim-strip-labels');
            const stripLabels = stripLabelsCheckbox ? stripLabelsCheckbox.checked : false;
            if (!scenarioId) return;

            simModalRunBtn.disabled = true;
            const originalHtml = simModalRunBtn.innerHTML;
            simModalRunBtn.innerHTML = '<span>TRIGGERING…</span> <i class="fa-solid fa-spinner fa-spin" aria-hidden="true"></i>';

            try {
                // 1. Activate scenario under the hood
                await api.activateSimScenario(scenarioId);
                // 2. Trigger run
                const res = await api.runSimScenario(scenarioId, rate, stripLabels);
                showNotification(`Simulation run for "${scenarioName}" triggered successfully!`, 'success');
                simModal.classList.add('hide');
                if (res.run_id) {
                    selectedRunId = res.run_id;
                }
                await loadSimulationsData();
            } catch (err) {
                showNotification(err.message || 'Failed to trigger simulation', 'error');
            } finally {
                simModalRunBtn.disabled = false;
                simModalRunBtn.innerHTML = originalHtml;
            }
        });
    }

    if (simRunsRefreshBtn) {
        simRunsRefreshBtn.addEventListener('click', async () => {
            const table = document.getElementById('sim-runs-tbody');
            await fetchWithLoader(
                { buttons: [simRunsRefreshBtn], container: table },
                async () => {
                    await loadSimRunsList();
                }
            );
        });
    }

    // Bulk Evaluations Rate Control & Triggers
    const bulkRateMinus = document.getElementById('bulk-rate-minus');
    const bulkRatePlus = document.getElementById('bulk-rate-plus');
    const bulkRateInput = document.getElementById('bulk-rate-input');
    const bulkTriggerBtn = document.getElementById('bulk-trigger-btn');
    const bulkRunsRefreshBtn = document.getElementById('bulk-runs-refresh-btn');
    const bulkClearSelectionBtn = document.getElementById('bulk-clear-selection-btn');
    const bulkSelectAllBtn = document.getElementById('bulk-select-all-btn');

    if (bulkRateMinus && bulkRateInput) {
        bulkRateMinus.addEventListener('click', () => {
            let val = parseFloat(bulkRateInput.value);
            if (val > 0.2) {
                val = parseFloat((val - 0.5).toFixed(1));
                if (val < 0.1) val = 0.1;
                bulkRateInput.value = val;
            }
        });
    }
    if (bulkRatePlus && bulkRateInput) {
        bulkRatePlus.addEventListener('click', () => {
            let val = parseFloat(bulkRateInput.value);
            if (val < 10.0) {
                val = parseFloat((val + 0.5).toFixed(1));
                bulkRateInput.value = val;
            }
        });
    }

    if (bulkClearSelectionBtn) {
        bulkClearSelectionBtn.addEventListener('click', () => {
            selectedBulkScenarioIds.clear();
            document.querySelectorAll('.bulk-sc-select-checkbox').forEach(cb => cb.checked = false);
            updateBulkControllerUI();
        });
    }

    if (bulkSelectAllBtn) {
        bulkSelectAllBtn.addEventListener('click', () => {
            document.querySelectorAll('.bulk-sc-select-checkbox').forEach(cb => {
                cb.checked = true;
                const scId = cb.getAttribute('data-scenario-id');
                if (scId) selectedBulkScenarioIds.add(scId);
            });
            updateBulkControllerUI();
        });
    }

    if (bulkTriggerBtn) {
        bulkTriggerBtn.addEventListener('click', async () => {
            if (selectedBulkScenarioIds.size === 0) return;
            const rate = parseFloat(bulkRateInput.value) || 1.0;
            const stripLabelsCheckbox = document.getElementById('bulk-strip-labels');
            const stripLabels = stripLabelsCheckbox ? stripLabelsCheckbox.checked : false;
            const runNameInput = document.getElementById('bulk-run-name-input');
            const runName = runNameInput.value.trim() || `Bulk Run ${new Date().toLocaleString()}`;

            bulkTriggerBtn.disabled = true;
            const triggerBtnText = document.getElementById('bulk-trigger-btn-text');
            if (triggerBtnText) {
                triggerBtnText.textContent = 'TRIGGERING BULK...';
            }

            try {
                const scenarioIds = [...selectedBulkScenarioIds];
                showNotification(`Triggering bulk evaluation run for ${scenarioIds.length} scenarios...`, 'info');
                
                const res = await api.triggerBulkRun(runName, scenarioIds, rate, stripLabels);
                
                showNotification(`Successfully started bulk evaluation run!`, 'success');
                selectedBulkScenarioIds.clear();
                document.querySelectorAll('.bulk-sc-select-checkbox').forEach(cb => cb.checked = false);
                runNameInput.value = '';
                updateBulkControllerUI();
                
                if (res.bulk_run_id) {
                    selectedBulkRunId = res.bulk_run_id;
                }
                await loadBulkEvalsData();
            } catch (err) {
                showNotification(err.message || 'Failed to trigger bulk evaluation', 'error');
            } finally {
                bulkTriggerBtn.disabled = false;
                updateBulkControllerUI();
            }
        });
    }

    if (bulkRunsRefreshBtn) {
        bulkRunsRefreshBtn.addEventListener('click', async () => {
            const table = document.getElementById('bulk-runs-tbody');
            await fetchWithLoader(
                { buttons: [bulkRunsRefreshBtn], container: table },
                async () => {
                    await loadBulkRunsList();
                }
            );
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
        } else if (state.activeView === 'simulations') {
            pollSimulationsData();
        } else if (state.activeView === 'bulk-evals') {
            pollBulkEvalsData();
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
        } else if (viewName === 'simulations') {
            loadSimulationsData();
        } else if (viewName === 'bulk-evals') {
            loadBulkEvalsData();
        } else if (viewName === 'settings') {
            loadSettingsForm();
        }
    }
});


// ==========================================
// 11. Attack Simulations View Controller
// ==========================================

let selectedRunId = null;
const selectedScenarioIds = new Set();

function updateBatchControllerUI() {
    const summary = document.getElementById('sim-batch-selection-summary');
    const triggerBtn = document.getElementById('sim-trigger-btn');
    const triggerBtnText = document.getElementById('sim-trigger-btn-text');
    if (!summary || !triggerBtn || !triggerBtnText) return;

    const count = selectedScenarioIds.size;
    if (count === 0) {
        summary.textContent = 'No scenarios selected. Select multiple scenarios in the catalog below.';
        triggerBtn.disabled = true;
        triggerBtnText.textContent = 'TRIGGER BATCH RUN (0)';
    } else {
        const names = [];
        const checkboxes = document.querySelectorAll('.sc-select-checkbox:checked');
        checkboxes.forEach(cb => {
            const name = cb.getAttribute('data-scenario-name');
            if (name) names.push(name);
        });
        
        if (names.length > 0) {
            const displayNames = names.slice(0, 3).join(', ');
            const suffix = names.length > 3 ? ` and ${names.length - 3} more` : '';
            summary.innerHTML = `<span style="color: var(--text-bright); font-weight: bold;">Selected (${count}):</span> ${escapeHtml(displayNames)}${suffix}`;
        } else {
            summary.innerHTML = `<span style="color: var(--text-bright); font-weight: bold;">Selected (${count}) scenarios</span>`;
        }
        triggerBtn.disabled = false;
        triggerBtnText.textContent = `TRIGGER BATCH RUN (${count})`;
    }
}

async function loadSimulationsData() {
    try {
        await Promise.all([
            loadSimStats(),
            loadSimScenariosList(),
            loadSimRunsList()
        ]);
        
        if (selectedRunId) {
            await renderRunDetails(selectedRunId);
        }
    } catch (err) {
        console.error('Failed to load simulations data:', err);
    }
}

async function pollSimulationsData() {
    try {
        await Promise.all([
            loadSimStats(),
            loadSimRunsList()
        ]);
        if (selectedRunId) {
            await renderRunDetails(selectedRunId);
        }
    } catch (err) {
        console.error('Error polling simulations:', err);
    }
}

async function loadSimStats() {
    try {
        const stats = await api.getSimStats();
        
        document.getElementById('sim-stat-runs').textContent = stats.total_runs || 0;
        document.getElementById('sim-stat-matched').textContent = stats.matched || 0;
        document.getElementById('sim-stat-mismatched').textContent = stats.mismatched || 0;
        document.getElementById('sim-stat-nobook').textContent = stats.no_playbook || 0;
        
        const accuracy = stats.accuracy_rate || 0.0;
        document.getElementById('sim-accuracy-val').textContent = `${accuracy}%`;
        
        const progressCircle = document.getElementById('sim-gauge-progress');
        if (progressCircle) {
            const strokeOffset = 251.2 - (251.2 * accuracy) / 100;
            progressCircle.setAttribute('stroke-dashoffset', strokeOffset);
        }
    } catch (err) {
        console.error('Failed to load sim stats:', err);
    }
}

const MITRE_NAMES = {
    "T1110": "Brute Force",
    "T1059": "Command and Scripting Interpreter",
    "T1047": "Windows Management Instrumentation",
    "T1569": "System Services",
    "T1021": "Remote Services",
    "T1053": "Scheduled Task/Job",
    "T1003": "OS Credential Dumping",
    "T1078": "Valid Accounts",
    "T1543": "Create or Modify System Process",
    "T1106": "Native API",
    "T1218": "System Binary Proxy Execution"
};

async function loadSimScenariosList() {
    const listContainer = document.getElementById('sim-scenario-list');
    if (!listContainer) return;
    
    try {
        const scenarios = await api.getSimScenarios();
        
        if (!scenarios || scenarios.length === 0) {
            listContainer.innerHTML = '<div class="tree-empty">No scenarios ingested yet. Run the AttackSimulator CLI to ingest scenarios.</div>';
            updateBatchControllerUI();
            return;
        }
        
        listContainer.innerHTML = '';
        
        // Group scenarios by MITRE ID
        const groups = {}; // mitreId -> Array of scenarios
        
        scenarios.forEach(sc => {
            const mitreIds = sc.mitre_ids || [];
            if (mitreIds.length === 0) {
                const key = "Other";
                if (!groups[key]) groups[key] = [];
                groups[key].push(sc);
            } else {
                mitreIds.forEach(id => {
                    const key = id;
                    if (!groups[key]) groups[key] = [];
                    if (!groups[key].some(s => s.id === sc.id)) {
                        groups[key].push(sc);
                    }
                });
            }
        });
        
        // Sort keys: alphabetically with "Other" last
        const sortedKeys = Object.keys(groups).sort((a, b) => {
            if (a === "Other") return 1;
            if (b === "Other") return -1;
            return a.localeCompare(b);
        });
        
        sortedKeys.forEach(techId => {
            const scList = groups[techId];
            const node = document.createElement('div');
            node.className = 'tree-node';
            
            const techName = techId === "Other" 
                ? "Other / Custom Scenarios" 
                : `${techId} - ${MITRE_NAMES[techId] || 'MITRE Technique'}`;
                
            node.innerHTML = `
                <div class="tree-header">
                    <i class="fa-solid fa-chevron-down tree-toggle-icon"></i>
                    <span>${escapeHtml(techName)} (${scList.length})</span>
                </div>
                <div class="tree-children"></div>
            `;
            
            const header = node.querySelector('.tree-header');
            const childrenContainer = node.querySelector('.tree-children');
            const toggleIcon = node.querySelector('.tree-toggle-icon');
            
            header.addEventListener('click', () => {
                const isCollapsed = toggleIcon.classList.toggle('collapsed');
                childrenContainer.classList.toggle('hide');
            });
            
            scList.forEach(sc => {
                const leaf = document.createElement('div');
                leaf.className = 'tree-leaf';
                const isChecked = selectedScenarioIds.has(sc.id) ? 'checked' : '';
                
                leaf.innerHTML = `
                    <div class="tree-leaf-checkbox-container" style="display: flex; align-items: center; margin-right: 10px;">
                        <input type="checkbox" class="sc-select-checkbox" data-scenario-id="${sc.id}" data-scenario-name="${escapeHtml(sc.name)}" ${isChecked} style="cursor: pointer; width: 14px; height: 14px; accent-color: var(--primary);">
                    </div>
                    <div style="min-width: 0; flex-grow: 1; margin-right: 8px;">
                        <div class="tree-leaf-title" title="${escapeHtml(sc.name)}">${escapeHtml(sc.name)}</div>
                        <span class="tree-leaf-desc">${escapeHtml(sc.description || 'No description.')}</span>
                    </div>
                    <div class="tree-leaf-actions">
                        <button class="btn btn-secondary btn-xs-padding-review view-sc-btn" title="View Details">
                            <i class="fa-solid fa-eye" aria-hidden="true"></i>
                        </button>
                        <button class="btn btn-primary btn-xs-padding-review run-sc-btn" title="Run Simulation">
                            <i class="fa-solid fa-play" aria-hidden="true"></i>
                        </button>
                    </div>
                `;
                
                const checkbox = leaf.querySelector('.sc-select-checkbox');
                checkbox.addEventListener('change', () => {
                    if (checkbox.checked) {
                        selectedScenarioIds.add(sc.id);
                    } else {
                        selectedScenarioIds.delete(sc.id);
                    }
                    updateBatchControllerUI();
                });
                
                const viewBtn = leaf.querySelector('.view-sc-btn');
                const runBtn = leaf.querySelector('.run-sc-btn');
                
                viewBtn.addEventListener('click', async (e) => {
                    e.stopPropagation();
                    
                    document.getElementById('sim-modal-name').textContent = sc.name;
                    document.getElementById('sim-modal-desc').textContent = sc.description || 'No description provided.';
                    document.getElementById('sim-modal-dataset').textContent = sc.source_dataset || 'custom';
                    document.getElementById('sim-modal-events').textContent = sc.total_events || 0;
                    document.getElementById('sim-modal-status').innerHTML = sc.status === 'active' 
                        ? `<span class="badge badge-info"><span class="pulse-cyan-dot"></span>Active</span>`
                        : `<span class="badge badge-muted">Passive</span>`;
                    
                    const mitreContainer = document.getElementById('sim-modal-mitre');
                    mitreContainer.innerHTML = (sc.mitre_ids || []).map(id => `<span>${escapeHtml(id)}</span>`).join(' ');
                    if (mitreContainer.innerHTML === '') mitreContainer.innerHTML = '<span>None</span>';
                    
                    const previewContainer = document.getElementById('sim-modal-events-preview');
                    previewContainer.innerHTML = '<div style="color: var(--text-muted);"><i class="fa-solid fa-spinner fa-spin" aria-hidden="true"></i> Loading sequence preview...</div>';
                    
                    const modalRunBtn = document.getElementById('sim-modal-run-btn');
                    if (modalRunBtn) {
                        modalRunBtn.setAttribute('data-scenario-id', sc.id);
                        modalRunBtn.setAttribute('data-scenario-name', sc.name);
                    }
                    
                    const modal = document.getElementById('sim-scenario-modal');
                    modal.classList.remove('hide');
                    
                    try {
                        const events = await api.getSimScenarioEvents(sc.id);
                        if (!events || events.length === 0) {
                            previewContainer.innerHTML = '<div style="color: var(--text-muted);">No events in this scenario.</div>';
                        } else {
                            previewContainer.innerHTML = events.map(ev => `
                                <div style="border-bottom: 1px solid rgba(255,255,255,0.04); padding: 6px 0; display: flex; justify-content: space-between; font-size: 11px;">
                                    <span>Seq ${ev.sequence_order}: Rule: <strong class="text-cyan">${escapeHtml(ev.correlation_rule || 'Unknown')}</strong></span>
                                    <span style="color: var(--text-muted);">${escapeHtml(ev.mitre_technique || 'N/A')}</span>
                                </div>
                            `).join('');
                        }
                    } catch (err) {
                        previewContainer.innerHTML = `<div class="text-error">Failed to load preview: ${escapeHtml(err.message)}</div>`;
                    }
                });
                
                runBtn.addEventListener('click', async (e) => {
                    e.stopPropagation();
                    runBtn.disabled = true;
                    const originalHtml = runBtn.innerHTML;
                    runBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin" aria-hidden="true"></i>';
                    
                    try {
                        const rate = parseFloat(document.getElementById('sim-rate-input').value) || 1.0;
                        const stripLabelsCheckbox = document.getElementById('sim-strip-labels');
                        const stripLabels = stripLabelsCheckbox ? stripLabelsCheckbox.checked : false;
                        await api.activateSimScenario(sc.id);
                        const res = await api.runSimScenario(sc.id, rate, stripLabels);
                        showNotification(`Simulation run for "${sc.name}" triggered successfully!`, 'success');
                        if (res.run_id) {
                            selectedRunId = res.run_id;
                        }
                        await loadSimulationsData();
                    } catch (err) {
                        showNotification(err.message || 'Failed to trigger simulation', 'error');
                    } finally {
                        runBtn.disabled = false;
                        runBtn.innerHTML = originalHtml;
                    }
                });
                
                childrenContainer.appendChild(leaf);
            });
            
            listContainer.appendChild(node);
        });
        
        updateBatchControllerUI();
        
    } catch (err) {
        console.error('Failed to load scenarios list:', err);
        listContainer.innerHTML = '<div class="tree-empty text-error">Failed to load scenarios.</div>';
    }
}

async function loadSimRunsList() {
    const tbody = document.getElementById('sim-runs-tbody');
    if (!tbody) return;
    
    try {
        const runs = await api.getSimRuns({ limit: 10 });
        
        if (!runs || runs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center" style="padding: 20px; color: var(--text-muted);">No simulation runs recorded.</td></tr>';
            return;
        }
        
        tbody.innerHTML = '';
        runs.forEach(run => {
            const tr = document.createElement('tr');
            if (selectedRunId === run.id) {
                tr.className = 'active-row';
            }
            
            const statusClass = run.status === 'COMPLETED' 
                ? 'badge-success' 
                : run.status === 'RUNNING' 
                ? 'badge-info' 
                : run.status === 'FAILED' 
                ? 'badge-error' 
                : 'badge-muted';
                
            const progress = run.total_events > 0 
                ? `${run.sent_events}/${run.total_events}`
                : '0/0';
                
            const stats = run.status === 'COMPLETED' 
                ? `<span class="text-emerald" style="font-family: var(--font-mono); font-weight: bold;">${run.matched_playbooks}M</span> / <span class="text-error" style="font-family: var(--font-mono); font-weight: bold;">${run.mismatched_playbooks}W</span> / <span class="text-amber" style="font-family: var(--font-mono); font-weight: bold;">${run.no_playbook}N</span>`
                : '-';
                
            tr.innerHTML = `
                <td style="font-family: var(--font-mono); font-size: 11px;">${escapeHtml(run.id.substring(0, 8))}…</td>
                <td style="font-weight: 500;">${escapeHtml(run.scenario_name || 'Deleted Scenario')}</td>
                <td><span class="badge ${statusClass}">${escapeHtml(run.status)}</span></td>
                <td style="font-family: var(--font-mono);">${escapeHtml(run.send_rate_per_sec)}/s</td>
                <td>${progress}</td>
                <td>${stats}</td>
                <td>${formatDate(run.created_at)}</td>
            `;
            
            tr.addEventListener('click', () => {
                tbody.querySelectorAll('tr').forEach(r => r.classList.remove('active-row'));
                tr.classList.add('active-row');
                selectedRunId = run.id;
                renderRunDetails(run.id);
            });
            
            tbody.appendChild(tr);
        });
    } catch (err) {
        console.error('Failed to load sim runs list:', err);
    }
}

async function renderRunDetails(runId) {
    const tbody = document.getElementById('sim-results-tbody');
    const detailIdBadge = document.getElementById('sim-run-detail-id');
    const detailSessionBadge = document.getElementById('sim-run-detail-session');
    const detailVerdictBadge = document.getElementById('sim-run-detail-verdict');
    const thSession = document.getElementById('sim-results-th-session');
    const thVerdict = document.getElementById('sim-results-th-verdict');
    if (!tbody || !detailIdBadge) return;
    
    try {
        const data = await api.getSimRunResults(runId);
        const results = data.results || [];
        
        detailIdBadge.textContent = `RUN: ${runId.substring(0, 18)}…`;
        detailIdBadge.classList.remove('hide');
        
        if (results.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center" style="padding: 20px; color: var(--text-muted);">No sequence events logged for this run.</td></tr>';
            if (detailSessionBadge) detailSessionBadge.classList.add('hide');
            if (detailVerdictBadge) detailVerdictBadge.classList.add('hide');
            if (thSession) thSession.classList.remove('hide');
            if (thVerdict) thVerdict.classList.remove('hide');
            return;
        }

        // Deduplication analysis
        const sessions = [...new Set(results.map(r => r.session_id).filter(Boolean))];
        const hasSingleSession = sessions.length <= 1;
        const singleSessionId = sessions.length === 1 ? sessions[0] : null;

        const verdicts = [...new Set(results.map(r => r.match_result).filter(Boolean))];
        const hasSingleVerdict = verdicts.length <= 1;
        const singleVerdict = verdicts.length === 1 ? verdicts[0] : null;

        if (detailSessionBadge) {
            if (singleSessionId) {
                detailSessionBadge.innerHTML = `SESSION: <a href="#" class="view-single-session text-cyan" data-session-id="${singleSessionId}" style="text-decoration: underline; font-family: var(--font-mono);">${escapeHtml(singleSessionId.substring(0, 8))}…</a>`;
                detailSessionBadge.classList.remove('hide');
                
                const singleLink = detailSessionBadge.querySelector('.view-single-session');
                if (singleLink) {
                    singleLink.addEventListener('click', (e) => {
                        e.preventDefault();
                        e.stopPropagation();
                        openSessionDetail(singleSessionId);
                    });
                }
            } else if (sessions.length > 1) {
                detailSessionBadge.textContent = 'SESSIONS: MULTIPLE';
                detailSessionBadge.classList.remove('hide');
            } else {
                detailSessionBadge.classList.add('hide');
            }
        }

        if (detailVerdictBadge) {
            if (singleVerdict) {
                const verdictClass = singleVerdict === 'CORRECT' 
                    ? 'badge-success' 
                    : singleVerdict === 'WRONG' 
                    ? 'badge-error' 
                    : singleVerdict === 'NO_PLAYBOOK' 
                    ? 'badge-warning' 
                    : 'badge-info';
                detailVerdictBadge.className = `badge ${verdictClass}`;
                detailVerdictBadge.textContent = `VERDICT: ${singleVerdict}`;
                detailVerdictBadge.classList.remove('hide');
            } else if (verdicts.length > 1) {
                detailVerdictBadge.className = 'badge badge-info';
                detailVerdictBadge.textContent = 'VERDICTS: MIXED';
                detailVerdictBadge.classList.remove('hide');
            } else {
                detailVerdictBadge.classList.add('hide');
            }
        }

        if (thSession) {
            if (hasSingleSession) {
                thSession.classList.add('hide');
            } else {
                thSession.classList.remove('hide');
            }
        }

        if (thVerdict) {
            if (hasSingleVerdict) {
                thVerdict.classList.add('hide');
            } else {
                thVerdict.classList.remove('hide');
            }
        }
        
        tbody.innerHTML = '';
        results.forEach(res => {
            const tr = document.createElement('tr');
            
            const verdictClass = res.match_result === 'CORRECT' 
                ? 'badge-success' 
                : res.match_result === 'WRONG' 
                ? 'badge-error' 
                : res.match_result === 'NO_PLAYBOOK' 
                ? 'badge-warning' 
                : 'badge-info';
                
            const sessionLink = res.session_id 
                ? `<a href="#" class="view-agent-session" data-session-id="${res.session_id}" style="color: var(--primary); font-family: var(--font-mono); font-size: 11px;">${escapeHtml(res.session_id.substring(0, 8))}…</a>`
                : '-';

            const sessionCell = hasSingleSession ? '' : `<td>${sessionLink}</td>`;
            const verdictCell = hasSingleVerdict ? '' : `<td><span class="badge ${verdictClass}">${escapeHtml(res.match_result)}</span></td>`;
                
            tr.innerHTML = `
                <td>
                    #${res.sequence_order}
                    <span class="view-raw-json-btn" style="cursor: pointer; margin-left: 6px;" title="View Raw Wazuh Alert Payload">
                        <i class="fa-solid fa-eye text-cyan"></i>
                    </span>
                </td>
                <td style="font-family: var(--font-mono);">${escapeHtml(res.mitre_technique || '-')}</td>
                <td style="font-family: var(--font-mono); font-size: 11px; max-width: 150px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(res.correlation_rule || '')}">${escapeHtml(res.correlation_rule || '-')}</td>
                ${sessionCell}
                <td style="font-family: var(--font-mono); font-size: 11px;">${escapeHtml(res.expected_playbook || 'None')}</td>
                <td style="font-family: var(--font-mono); font-size: 11px;">${escapeHtml(res.actual_playbook || 'None')}</td>
                ${verdictCell}
            `;
            
            const link = tr.querySelector('.view-agent-session');
            if (link) {
                link.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    openSessionDetail(res.session_id);
                });
            }

            const jsonBtn = tr.querySelector('.view-raw-json-btn');
            if (jsonBtn) {
                jsonBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    const codeBlock = document.getElementById('sim-json-code-block');
                    const modal = document.getElementById('sim-json-modal');
                    if (codeBlock && modal) {
                        let alertObj = res.wazuh_alert;
                        if (typeof alertObj === 'string') {
                            try {
                                alertObj = JSON.parse(alertObj);
                            } catch (err) {
                                console.error('Failed to parse wazuh_alert JSON string:', err);
                            }
                        }
                        codeBlock.textContent = alertObj 
                            ? JSON.stringify(alertObj, null, 2) 
                            : 'No wazuh alert payload recorded for this event.';
                        modal.classList.remove('hide');
                    }
                });
            }
            
            tbody.appendChild(tr);
        });
    } catch (err) {
        console.error('Failed to load run details:', err);
        tbody.innerHTML = '<tr><td colspan="7" class="text-center text-error" style="padding: 20px;">Failed to load run audit sequence.</td></tr>';
    }
}


// ==========================================
// 12. Bulk Evaluations View Controller
// ==========================================

const selectedBulkScenarioIds = new Set();
let selectedBulkRunId = null;

function updateBulkControllerUI() {
    const summary = document.getElementById('bulk-selection-summary');
    const triggerBtn = document.getElementById('bulk-trigger-btn');
    const triggerBtnText = document.getElementById('bulk-trigger-btn-text');
    if (!summary || !triggerBtn || !triggerBtnText) return;

    const count = selectedBulkScenarioIds.size;
    if (count === 0) {
        summary.textContent = 'No scenarios selected. Select scenarios from the catalog below.';
        triggerBtn.disabled = true;
        triggerBtnText.textContent = 'TRIGGER BULK RUN (0)';
    } else {
        const names = [];
        const checkboxes = document.querySelectorAll('.bulk-sc-select-checkbox:checked');
        const uniqueNames = new Set();
        checkboxes.forEach(cb => {
            const name = cb.getAttribute('data-scenario-name');
            if (name) uniqueNames.add(name);
        });
        uniqueNames.forEach(name => names.push(name));
        
        if (names.length > 0) {
            const displayNames = names.slice(0, 3).join(', ');
            const suffix = names.length > 3 ? ` and ${names.length - 3} more` : '';
            summary.innerHTML = `<span style="color: var(--text-bright); font-weight: bold;">Selected (${count}):</span> ${escapeHtml(displayNames)}${suffix}`;
        } else {
            summary.innerHTML = `<span style="color: var(--text-bright); font-weight: bold;">Selected (${count}) scenarios</span>`;
        }
        triggerBtn.disabled = false;
        triggerBtnText.textContent = `TRIGGER BULK RUN (${count})`;
    }

    // Update group checkboxes (checked and indeterminate states)
    const groupNodes = document.querySelectorAll('#bulk-scenario-list .tree-node');
    groupNodes.forEach(node => {
        const groupCheckbox = node.querySelector('.bulk-group-select-checkbox');
        if (!groupCheckbox) return;
        
        const childCheckboxes = node.querySelectorAll('.bulk-sc-select-checkbox');
        let checkedCount = 0;
        childCheckboxes.forEach(cb => {
            if (cb.checked) checkedCount++;
        });
        
        if (checkedCount === 0) {
            groupCheckbox.checked = false;
            groupCheckbox.indeterminate = false;
        } else if (checkedCount === childCheckboxes.length) {
            groupCheckbox.checked = true;
            groupCheckbox.indeterminate = false;
        } else {
            groupCheckbox.checked = false;
            groupCheckbox.indeterminate = true;
        }
    });
}

async function loadBulkEvalsData() {
    try {
        await Promise.all([
            loadActiveLlmInfo(),
            loadBulkStats(),
            loadBulkScenariosList(),
            loadBulkRunsList()
        ]);
        
        if (selectedBulkRunId) {
            await renderBulkRunDetails(selectedBulkRunId);
        }
    } catch (err) {
        console.error('Failed to load bulk evaluations data:', err);
    }
}

async function pollBulkEvalsData() {
    try {
        await Promise.all([
            loadBulkStats(),
            loadBulkRunsList()
        ]);
        if (selectedBulkRunId) {
            await renderBulkRunDetails(selectedBulkRunId);
        }
    } catch (err) {
        console.error('Error polling bulk evaluations:', err);
    }
}

async function loadActiveLlmInfo() {
    const activeLlmBadge = document.getElementById('bulk-active-llm');
    if (!activeLlmBadge) return;
    try {
        const info = await api.getActiveLlmInfo();
        activeLlmBadge.textContent = `🤖 LLM: ${info.provider.toUpperCase()} / ${info.model}`;
    } catch (err) {
        console.error('Failed to load active LLM settings:', err);
        activeLlmBadge.textContent = `🤖 LLM: Error loading settings`;
    }
}

async function loadBulkStats() {
    try {
        const stats = await api.getSimStats();
        
        document.getElementById('bulk-stat-runs').textContent = stats.total_runs || 0;
        document.getElementById('bulk-stat-matched').textContent = stats.matched || 0;
        document.getElementById('bulk-stat-mismatched').textContent = stats.mismatched || 0;
        document.getElementById('bulk-stat-nobook').textContent = stats.no_playbook || 0;
        
        const accuracy = stats.accuracy_rate || 0.0;
        document.getElementById('bulk-accuracy-val').textContent = `${accuracy}%`;
        
        const progressCircle = document.getElementById('bulk-gauge-progress');
        if (progressCircle) {
            const strokeOffset = 251.2 - (251.2 * accuracy) / 100;
            progressCircle.setAttribute('stroke-dashoffset', strokeOffset);
        }
    } catch (err) {
        console.error('Failed to load bulk statistics:', err);
    }
}

async function loadBulkScenariosList() {
    const listContainer = document.getElementById('bulk-scenario-list');
    if (!listContainer) return;
    
    try {
        const dataset = await api.getSimScenarios();
        
        if (!dataset || dataset.length === 0) {
            listContainer.innerHTML = '<div class="tree-empty">No scenarios configured in simulator database.</div>';
            return;
        }
        
        // Group scenarios by MITRE ID
        const groups = {}; // mitreId -> Array of scenarios
        
        dataset.forEach(sc => {
            const mitreIds = sc.mitre_ids || [];
            if (mitreIds.length === 0) {
                const key = "Other";
                if (!groups[key]) groups[key] = [];
                groups[key].push(sc);
            } else {
                mitreIds.forEach(id => {
                    const key = id;
                    if (!groups[key]) groups[key] = [];
                    if (!groups[key].some(s => s.id === sc.id)) {
                        groups[key].push(sc);
                    }
                });
            }
        });
        
        // Sort keys: alphabetically with "Other" last
        const sortedKeys = Object.keys(groups).sort((a, b) => {
            if (a === "Other") return 1;
            if (b === "Other") return -1;
            return a.localeCompare(b);
        });
        
        listContainer.innerHTML = '';
        
        sortedKeys.forEach(techId => {
            const scList = groups[techId];
            const node = document.createElement('div');
            node.className = 'tree-node';
            
            const techName = techId === "Other" 
                ? "Other / Custom Scenarios" 
                : `${techId} - ${MITRE_NAMES[techId] || 'MITRE Technique'}`;
                
            node.innerHTML = `
                <div class="tree-header" style="display: flex; align-items: center; gap: 8px;">
                    <i class="fa-solid fa-chevron-down tree-toggle-icon" style="cursor: pointer; padding: 4px;"></i>
                    <input type="checkbox" class="bulk-group-select-checkbox" data-group-id="${escapeHtml(techId)}" style="cursor: pointer; width: 14px; height: 14px; accent-color: var(--primary);">
                    <span style="flex-grow: 1; cursor: pointer; user-select: none;">${escapeHtml(techName)} (${scList.length})</span>
                </div>
                <div class="tree-children"></div>
            `;
            
            const header = node.querySelector('.tree-header');
            const childrenContainer = node.querySelector('.tree-children');
            const toggleIcon = node.querySelector('.tree-toggle-icon');
            const groupCheckbox = node.querySelector('.bulk-group-select-checkbox');
            
            header.addEventListener('click', (e) => {
                if (e.target.closest('.bulk-group-select-checkbox')) {
                    return;
                }
                const isCollapsed = toggleIcon.classList.toggle('collapsed');
                childrenContainer.classList.toggle('hide');
            });
            
            groupCheckbox.addEventListener('change', (e) => {
                const isChecked = e.target.checked;
                const childCheckboxes = childrenContainer.querySelectorAll('.bulk-sc-select-checkbox');
                childCheckboxes.forEach(cb => {
                    const scId = cb.getAttribute('data-scenario-id');
                    if (isChecked) {
                        selectedBulkScenarioIds.add(scId);
                    } else {
                        selectedBulkScenarioIds.delete(scId);
                    }
                    
                    // Sync all checkboxes on the page for this scenario ID
                    document.querySelectorAll(`.bulk-sc-select-checkbox[data-scenario-id="${scId}"]`).forEach(oCb => {
                        oCb.checked = isChecked;
                    });
                });
                updateBulkControllerUI();
            });
            
            scList.sort((a,b) => a.name.localeCompare(b.name)).forEach(sc => {
                const leaf = document.createElement('div');
                leaf.className = 'tree-leaf';
                leaf.style.paddingLeft = '32px';
                
                const checked = selectedBulkScenarioIds.has(sc.id) ? 'checked' : '';
                
                leaf.innerHTML = `
                    <label style="display: flex; align-items: center; gap: 10px; width: 100%; cursor: pointer; user-select: none; margin: 0;">
                        <input type="checkbox" class="bulk-sc-select-checkbox" data-scenario-id="${sc.id}" data-scenario-name="${escapeHtml(sc.name)}" ${checked} style="cursor: pointer; width: 13px; height: 13px; accent-color: var(--primary);">
                        <div style="min-width: 0; flex-grow: 1;">
                            <div class="tree-leaf-title" title="${escapeHtml(sc.name)}">${escapeHtml(sc.name)}</div>
                            <span class="tree-leaf-desc">${escapeHtml(sc.description || 'No description.')}</span>
                        </div>
                        <span style="color: var(--text-muted); font-size: 10px; white-space: nowrap; margin-left: auto;">(${sc.total_events || 0} events)</span>
                    </label>
                `;
                
                const checkbox = leaf.querySelector('.bulk-sc-select-checkbox');
                checkbox.addEventListener('change', (e) => {
                    const isChecked = e.target.checked;
                    if (isChecked) {
                        selectedBulkScenarioIds.add(sc.id);
                    } else {
                        selectedBulkScenarioIds.delete(sc.id);
                    }
                    
                    // Sync all checkboxes on the page for this scenario ID
                    document.querySelectorAll(`.bulk-sc-select-checkbox[data-scenario-id="${sc.id}"]`).forEach(oCb => {
                        oCb.checked = isChecked;
                    });
                    
                    updateBulkControllerUI();
                });
                
                childrenContainer.appendChild(leaf);
            });
            
            listContainer.appendChild(node);
        });
        
        updateBulkControllerUI();
        
    } catch (err) {
        console.error('Failed to load scenarios list:', err);
        listContainer.innerHTML = '<div class="tree-empty text-error">Failed to load scenarios.</div>';
    }
}

async function loadBulkRunsList() {
    const tbody = document.getElementById('bulk-runs-tbody');
    if (!tbody) return;
    
    try {
        const runs = await api.getBulkRuns({ limit: 10 });
        
        if (!runs || runs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center" style="padding: 20px; color: var(--text-muted);">No bulk runs recorded.</td></tr>';
            return;
        }
        
        tbody.innerHTML = '';
        runs.forEach(run => {
            const tr = document.createElement('tr');
            if (selectedBulkRunId === run.id) {
                tr.className = 'active-row';
            }
            
            const statusClass = run.status === 'COMPLETED' 
                ? 'badge-success' 
                : run.status === 'RUNNING' 
                ? 'badge-info' 
                : run.status === 'FAILED' 
                ? 'badge-error' 
                : 'badge-muted';
                
            const total = run.total_scenarios || 0;
            const completed = run.completed_scenarios || 0;
            
            // Calculate accuracy rate for completed ones
            const matched = run.matched_playbooks || 0;
            const mismatched = run.mismatched_playbooks || 0;
            const nobook = run.no_playbook || 0;
            const totalFinished = matched + mismatched + nobook;
            const accuracy = totalFinished > 0 ? `${Math.round((matched / totalFinished) * 100)}%` : '0%';
                
            tr.innerHTML = `
                <td style="font-family: var(--font-mono); font-size: 11px;">${escapeHtml(run.id.substring(0, 8))}…</td>
                <td style="font-weight: 500;">${escapeHtml(run.name)}</td>
                <td style="font-family: var(--font-mono); font-size: 11px;">${escapeHtml(run.llm_model || 'Unknown')}</td>
                <td><span class="badge ${run.strip_labels ? 'badge-warning' : 'badge-muted'}">${run.strip_labels ? 'YES' : 'NO'}</span></td>
                <td><span class="badge ${statusClass}">${escapeHtml(run.status)} (${completed}/${total})</span></td>
                <td style="font-family: var(--font-mono); font-weight: bold; color: ${totalFinished > 0 ? 'var(--secondary)' : 'var(--text-muted)'}">${accuracy}</td>
                <td>${formatDate(run.created_at)}</td>
            `;
            
            tr.addEventListener('click', () => {
                tbody.querySelectorAll('tr').forEach(r => r.classList.remove('active-row'));
                tr.classList.add('active-row');
                selectedBulkRunId = run.id;
                renderBulkRunDetails(run.id);
            });
            
            tbody.appendChild(tr);
        });
    } catch (err) {
        console.error('Failed to load bulk runs list:', err);
    }
}

async function renderBulkRunDetails(bulkRunId) {
    const tbody = document.getElementById('bulk-detail-tbody');
    const nameBadge = document.getElementById('bulk-detail-name-badge');
    if (!tbody || !nameBadge) return;
    
    try {
        const data = await api.getBulkRunResults(bulkRunId);
        const runs = data.runs || [];
        const bulk = data.bulk_run || {};
        
        nameBadge.textContent = `BULK RUN: ${bulk.name || bulkRunId.substring(0, 8)}`;
        nameBadge.classList.remove('hide');
        
        if (runs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center" style="padding: 20px; color: var(--text-muted);">No scenario runs found under this bulk run.</td></tr>';
            return;
        }
        
        tbody.innerHTML = '';
        runs.forEach(run => {
            const tr = document.createElement('tr');
            
            const statusClass = run.status === 'COMPLETED' 
                ? 'badge-success' 
                : run.status === 'RUNNING' 
                ? 'badge-info' 
                : run.status === 'FAILED' 
                ? 'badge-error' 
                : 'badge-muted';
                
            const progress = run.total_events > 0 
                ? `${run.sent_events}/${run.total_events}`
                : '0/0';
                
            tr.innerHTML = `
                <td style="font-weight: 500;">${escapeHtml(run.scenario_name || 'Deleted Scenario')}</td>
                <td><span class="badge ${statusClass}">${escapeHtml(run.status)}</span></td>
                <td>${progress}</td>
                <td class="text-emerald" style="font-family: var(--font-mono); font-weight: bold;">${run.matched_playbooks || 0}</td>
                <td class="text-error" style="font-family: var(--font-mono); font-weight: bold;">${run.mismatched_playbooks || 0}</td>
                <td class="text-warning" style="font-family: var(--font-mono); font-weight: bold;">${run.no_playbook || 0}</td>
                <td>
                    <button type="button" class="btn btn-secondary view-sequence-btn" data-run-id="${run.id}" style="padding: 2px 6px; font-size: 10px; line-height: 1.2;">
                        <i class="fa-solid fa-eye" aria-hidden="true"></i> View Sequence
                    </button>
                </td>
            `;
            
            const btn = tr.querySelector('.view-sequence-btn');
            if (btn) {
                btn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    selectedRunId = run.id;
                    switchView('simulations');
                });
            }
            
            tbody.appendChild(tr);
        });
    } catch (err) {
        console.error('Failed to load bulk run details:', err);
        tbody.innerHTML = '<tr><td colspan="7" class="text-center text-error" style="padding: 20px;">Failed to load bulk run details.</td></tr>';
    }
}

