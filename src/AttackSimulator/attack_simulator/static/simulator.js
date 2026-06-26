// Attack Simulator Web UI Controller

// Global App State
const state = {
    activePanel: 'panel-scenarios',
    scenarios: [],
    runs: [],
    bulkRuns: [],
    selectedScenarioId: null,
    selectedRunId: null,
    selectedBulkRunId: null,
    stats: {
        total_runs: 0,
        matched: 0,
        mismatched: 0,
        no_playbook: 0,
        accuracy_rate: 0.0
    }
};

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

const selectedBulkScenarioIds = new Set();

// API Client Wrapper
const api = {
    async get(path) {
        try {
            const response = await fetch(`/v1${path}`);
            if (!response.ok) {
                const text = await response.text();
                throw new Error(text || `HTTP error ${response.status}`);
            }
            return await response.json();
        } catch (error) {
            console.error(`API GET error on ${path}:`, error);
            showToast(error.message || 'Network request failed', 'error');
            throw error;
        }
    },

    async post(path, body = null, params = {}) {
        try {
            const url = new URL(`/v1${path}`, window.location.origin);
            Object.entries(params).forEach(([k, v]) => url.searchParams.append(k, v));

            const options = {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            };
            if (body) options.body = JSON.stringify(body);

            const response = await fetch(url, options);
            if (!response.ok) {
                const text = await response.text();
                throw new Error(text || `HTTP error ${response.status}`);
            }
            return await response.json();
        } catch (error) {
            console.error(`API POST error on ${path}:`, error);
            showToast(error.message || 'Operation failed', 'error');
            throw error;
        }
    }
};

// DOM Loading and Startup
document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initEventListeners();
    refreshAllData();

    // Start background pollers
    setInterval(pollActiveRuns, 8000);
});

// Navigation Handling
function initNavigation() {
    const navItems = document.querySelectorAll('.side-nav .nav-item');
    navItems.forEach(item => {
        item.addEventListener('click', () => {
            const target = item.getAttribute('data-target');
            if (!target) return;

            // Update active nav link
            navItems.forEach(n => n.classList.remove('active'));
            item.classList.add('active');

            // Switch active panel
            document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
            const activePanel = document.getElementById(target);
            if (activePanel) activePanel.classList.add('active');

            state.activePanel = target;
            onPanelSwitch(target);
        });
    });
}

function onPanelSwitch(panelId) {
    if (panelId === 'panel-scenarios') {
        loadScenarios();
    } else if (panelId === 'panel-runs') {
        loadRuns();
        loadStats();
    } else if (panelId === 'panel-bulk') {
        loadBulkRuns();
        loadBulkScenariosList();
    }
}

// Event Listeners
function initEventListeners() {
    // Global sync button
    document.getElementById('global-refresh-btn').addEventListener('click', async () => {
        const btn = document.getElementById('global-refresh-btn');
        btn.disabled = true;
        const icon = btn.querySelector('i');
        icon.className = 'fa-solid fa-arrows-rotate fa-spin';
        try {
            await refreshAllData();
            showToast('All status synced successfully', 'success');
        } finally {
            btn.disabled = false;
            icon.className = 'fa-solid fa-arrows-rotate';
        }
    });

    // Individual Scenario Execution Timing Mode Controller
    const scTimingMode = document.getElementById('sc-timing-mode');
    const scRateRow = document.getElementById('sc-rate-row');
    const scMaxDelayRow = document.getElementById('sc-max-delay-row');

    if (scTimingMode && scRateRow && scMaxDelayRow) {
        scTimingMode.addEventListener('change', () => {
            if (scTimingMode.value === 'original') {
                scRateRow.style.display = 'none';
                scMaxDelayRow.style.display = 'flex';
            } else {
                scRateRow.style.display = 'flex';
                scMaxDelayRow.style.display = 'none';
            }
        });
    }

    // Individual Scenario Execution Rate Controller
    const scRateMinus = document.getElementById('sc-rate-minus');
    const scRatePlus = document.getElementById('sc-rate-plus');
    const scRateInput = document.getElementById('sc-rate-input');

    if (scRateMinus && scRatePlus && scRateInput) {
        scRateMinus.addEventListener('click', () => {
            let val = parseFloat(scRateInput.value) || 1.0;
            if (val > 0.2) {
                val = parseFloat((val - 0.5).toFixed(1));
                if (val < 0.1) val = 0.1;
                scRateInput.value = val;
            }
        });
        scRatePlus.addEventListener('click', () => {
            let val = parseFloat(scRateInput.value) || 1.0;
            if (val < 10.0) {
                val = parseFloat((val + 0.5).toFixed(1));
                scRateInput.value = val;
            }
        });
    }

    // Individual Scenario Max Delay Controller
    const scMaxDelayMinus = document.getElementById('sc-max-delay-minus');
    const scMaxDelayPlus = document.getElementById('sc-max-delay-plus');
    const scMaxDelayInput = document.getElementById('sc-max-delay-input');

    if (scMaxDelayMinus && scMaxDelayPlus && scMaxDelayInput) {
        scMaxDelayMinus.addEventListener('click', () => {
            let val = parseInt(scMaxDelayInput.value) || 30;
            if (val > 5) {
                val -= 5;
                scMaxDelayInput.value = `${val}s`;
            }
        });
        scMaxDelayPlus.addEventListener('click', () => {
            let val = parseInt(scMaxDelayInput.value) || 30;
            if (val < 120) {
                val += 5;
                scMaxDelayInput.value = `${val}s`;
            }
        });
    }

    // Trigger Single Scenario Simulation Run
    const triggerBtn = document.getElementById('sc-trigger-btn');
    if (triggerBtn) {
        triggerBtn.addEventListener('click', async () => {
            if (!state.selectedScenarioId) return;
            const timingMode = scTimingMode ? scTimingMode.value : 'constant';
            const rate = parseFloat(scRateInput.value) || 1.0;
            const maxDelay = scMaxDelayInput ? parseFloat(scMaxDelayInput.value) || 30.0 : 30.0;
            const strip = document.getElementById('sc-strip-labels').checked;

            triggerBtn.disabled = true;
            triggerBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Triggering...';

            try {
                // 1. Activate scenario
                await api.post(`/simulations/scenarios/${state.selectedScenarioId}/activate`);
                // 2. Trigger run
                const res = await api.post(`/simulations/scenarios/${state.selectedScenarioId}/run`, null, {
                    send_rate_per_sec: rate,
                    strip_labels: strip,
                    timing_mode: timingMode,
                    max_original_delay: maxDelay
                });
                showToast(`Simulation started! Run ID: ${res.run_id}`, 'success');
                // Switch to runs panel to monitor
                document.querySelector('[data-target="panel-runs"]').click();
            } catch (err) {
                console.error(err);
            } finally {
                triggerBtn.disabled = false;
                triggerBtn.innerHTML = '<i class="fa-solid fa-play"></i> Trigger Simulation';
            }
        });
    }

    // Bulk Scenario Select All
    const selectAllBtn = document.getElementById('bulk-select-all');
    if (selectAllBtn) {
        selectAllBtn.addEventListener('click', () => {
            const checkboxes = document.querySelectorAll('.bulk-sc-select-checkbox');
            const allChecked = Array.from(checkboxes).every(cb => cb.checked);
            checkboxes.forEach(cb => {
                cb.checked = !allChecked;
                const scId = cb.getAttribute('data-scenario-id');
                if (!allChecked) {
                    selectedBulkScenarioIds.add(scId);
                } else {
                    selectedBulkScenarioIds.delete(scId);
                }
            });
            updateBulkControllerUI();
        });
    }

    // Bulk Execution Timing Mode Controller
    const bulkTimingMode = document.getElementById('bulk-timing-mode');
    const bulkRateRow = document.getElementById('bulk-rate-row');
    const bulkMaxDelayRow = document.getElementById('bulk-max-delay-row');

    if (bulkTimingMode && bulkRateRow && bulkMaxDelayRow) {
        bulkTimingMode.addEventListener('change', () => {
            if (bulkTimingMode.value === 'original') {
                bulkRateRow.style.display = 'none';
                bulkMaxDelayRow.style.display = 'flex';
            } else {
                bulkRateRow.style.display = 'flex';
                bulkMaxDelayRow.style.display = 'none';
            }
        });
    }

    // Bulk Execution Rate Controller
    const bulkRateMinus = document.getElementById('bulk-rate-minus');
    const bulkRatePlus = document.getElementById('bulk-rate-plus');
    const bulkRateInput = document.getElementById('bulk-rate-input');

    if (bulkRateMinus && bulkRatePlus && bulkRateInput) {
        bulkRateMinus.addEventListener('click', () => {
            let val = parseFloat(bulkRateInput.value) || 1.0;
            if (val > 0.2) {
                val = parseFloat((val - 0.5).toFixed(1));
                if (val < 0.1) val = 0.1;
                bulkRateInput.value = val;
            }
        });
        bulkRatePlus.addEventListener('click', () => {
            let val = parseFloat(bulkRateInput.value) || 1.0;
            if (val < 10.0) {
                val = parseFloat((val + 0.5).toFixed(1));
                bulkRateInput.value = val;
            }
        });
    }

    // Bulk Execution Max Delay Controller
    const bulkMaxDelayMinus = document.getElementById('bulk-max-delay-minus');
    const bulkMaxDelayPlus = document.getElementById('bulk-max-delay-plus');
    const bulkMaxDelayInput = document.getElementById('bulk-max-delay-input');

    if (bulkMaxDelayMinus && bulkMaxDelayPlus && bulkMaxDelayInput) {
        bulkMaxDelayMinus.addEventListener('click', () => {
            let val = parseInt(bulkMaxDelayInput.value) || 30;
            if (val > 5) {
                val -= 5;
                bulkMaxDelayInput.value = `${val}s`;
            }
        });
        bulkMaxDelayPlus.addEventListener('click', () => {
            let val = parseInt(bulkMaxDelayInput.value) || 30;
            if (val < 120) {
                val += 5;
                bulkMaxDelayInput.value = `${val}s`;
            }
        });
    }

    // Trigger Bulk Run
    const bulkBtn = document.getElementById('bulk-execute-btn');
    if (bulkBtn) {
        bulkBtn.addEventListener('click', async () => {
            const name = document.getElementById('bulk-name-input').value.trim() || `Bulk Run ${new Date().toLocaleString()}`;
            const timingMode = bulkTimingMode ? bulkTimingMode.value : 'constant';
            const rate = parseFloat(bulkRateInput.value) || 1.0;
            const maxDelay = bulkMaxDelayInput ? parseFloat(bulkMaxDelayInput.value) || 30.0 : 30.0;
            const strip = document.getElementById('bulk-strip-labels').checked;
            
            // Get selected IDs
            const selectedIds = Array.from(selectedBulkScenarioIds);

            if (selectedIds.length === 0) {
                showToast('Please select at least one scenario to execute bulk test.', 'error');
                return;
            }

            bulkBtn.disabled = true;
            bulkBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Triggering Bulk...';

            try {
                const res = await api.post('/simulations/bulk-runs', {
                    name: name,
                    scenario_ids: selectedIds,
                    send_rate_per_sec: rate,
                    strip_labels: strip,
                    timing_mode: timingMode,
                    max_original_delay: maxDelay
                });
                showToast(`Bulk Run successfully started in background!`, 'success');
                document.getElementById('bulk-name-input').value = '';
                
                // Clear selection
                selectedBulkScenarioIds.clear();
                document.querySelectorAll('.bulk-sc-select-checkbox').forEach(cb => cb.checked = false);
                updateBulkControllerUI();

                // Reload list
                await loadBulkRuns();
            } catch (err) {
                console.error(err);
            } finally {
                bulkBtn.disabled = false;
                updateBulkControllerUI();
            }
        });
    }

    // Events Modal close handlers
    const modal = document.getElementById('events-modal');
    const closeBtn = document.getElementById('close-modal-btn');
    if (modal && closeBtn) {
        closeBtn.addEventListener('click', () => {
            modal.style.display = 'none';
        });
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.style.display = 'none';
            }
        });
    }
}

// Global Refresh Data
async function refreshAllData() {
    onPanelSwitch(state.activePanel);
}

// Background poller to refresh active simulation runs
async function pollActiveRuns() {
    if (state.activePanel === 'panel-runs') {
        const hasActive = state.runs.some(r => r.status === 'RUNNING');
        if (hasActive) {
            await loadRuns();
            await loadStats();
            if (state.selectedRunId) {
                await loadRunAuditDetails(state.selectedRunId);
            }
        }
    } else if (state.activePanel === 'panel-bulk') {
        const hasActiveBulk = state.bulkRuns.some(b => b.status === 'RUNNING');
        if (hasActiveBulk) {
            await loadBulkRuns();
            if (state.selectedBulkRunId) {
                await loadBulkDetails(state.selectedBulkRunId);
            }
        }
    }
}

// 1. SCENARIOS SECTION
async function loadScenarios() {
    const list = document.getElementById('scenarios-list');
    try {
        const scenarios = await api.get('/simulations/scenarios');
        state.scenarios = scenarios;

        if (scenarios.length === 0) {
            list.innerHTML = '<div class="empty-placeholder"><i class="fa-solid fa-info"></i><p>No scenarios found in database.</p></div>';
            return;
        }

        list.innerHTML = '';
        scenarios.forEach(sc => {
            const card = document.createElement('div');
            card.className = `scenario-card ${state.selectedScenarioId === sc.id ? 'active' : ''}`;
            card.setAttribute('data-id', sc.id);

            const statusClass = sc.status === 'active' ? 'badge-active' : 'badge-passive';
            const techniquesCount = sc.mitre_ids ? sc.mitre_ids.length : 0;
            const isDagBadge = sc.type === 'dag' ? '<span class="badge badge-info" style="margin-left: 6px; font-size: 9px; padding: 1px 4px;">DAG</span>' : '';

            card.innerHTML = `
                <div class="sc-header">
                    <span class="sc-name">${escapeHtml(sc.name)} ${isDagBadge}</span>
                    <span class="badge ${statusClass}">${escapeHtml(sc.status)}</span>
                </div>
                <p class="sc-desc">${escapeHtml(sc.description || 'No description available')}</p>
                <div class="sc-meta">
                    <span>${techniquesCount} MITRE Techniques</span>
                    <span>${sc.total_events} Correlated Events</span>
                </div>
            `;

            card.addEventListener('click', () => {
                document.querySelectorAll('.scenario-card').forEach(c => c.classList.remove('active'));
                card.classList.add('active');
                state.selectedScenarioId = sc.id;
                showScenarioDetail(sc);
            });

            list.appendChild(card);
        });

        // Autoselect first scenario if none is selected
        if (!state.selectedScenarioId && scenarios.length > 0) {
            list.children[0].click();
        } else if (state.selectedScenarioId) {
            const activeSc = scenarios.find(s => s.id === state.selectedScenarioId);
            if (activeSc) showScenarioDetail(activeSc);
        }
    } catch (err) {
        list.innerHTML = '<div class="empty-placeholder"><i class="fa-solid fa-triangle-exclamation"></i><p>Failed to load scenarios.</p></div>';
    }
}

async function showScenarioDetail(sc) {
    document.getElementById('scenario-detail-empty').style.display = 'none';
    const content = document.getElementById('scenario-detail-content');
    content.style.display = 'flex';

    document.getElementById('detail-sc-name').textContent = sc.name;
    document.getElementById('detail-sc-desc').textContent = sc.description || 'No description available';
    document.getElementById('detail-sc-events-count').textContent = sc.total_events || 0;

    // Load MITRE chips
    const mitre = document.getElementById('detail-sc-mitre');
    mitre.innerHTML = '';
    if (sc.mitre_ids && sc.mitre_ids.length > 0) {
        sc.mitre_ids.forEach(tid => {
            const chip = document.createElement('span');
            chip.className = 'mitre-chip';
            chip.textContent = tid;
            mitre.appendChild(chip);
        });
    } else {
        mitre.innerHTML = '<span class="text-muted" style="font-size: 12px;">No MITRE techniques mapped</span>';
    }

    // Load event preview list
    const preview = document.getElementById('detail-sc-events');
    preview.innerHTML = '<div class="text-center" style="padding: 10px;"><i class="fa-solid fa-spinner fa-spin"></i> Loading event preview...</div>';

    if (sc.type === 'dag' && sc.dag_structure) {
        preview.innerHTML = '';
        const steps = sc.dag_structure.steps || {};
        for (const [stepKey, stepInfo] of Object.entries(steps)) {
            const stepDiv = document.createElement('div');
            stepDiv.style.marginBottom = '12px';
            stepDiv.style.padding = '10px';
            stepDiv.style.border = '1px solid rgba(255,255,255,0.06)';
            stepDiv.style.borderRadius = '6px';
            stepDiv.style.background = 'rgba(0,0,0,0.2)';

            const transitions = stepInfo.next || {};
            let transHtml = '';
            if (Object.keys(transitions).length > 0) {
                transHtml = `<div style="margin-top: 6px; font-size: 11px; color: var(--text-muted); display: flex; flex-direction: column; gap: 4px;">` +
                    Object.entries(transitions).map(([verdict, nextStep]) => {
                        return `<span>• If <strong style="color: var(--primary);">${escapeHtml(verdict)}</strong> ➔ <span style="color: var(--text-bright);">${escapeHtml(nextStep)}</span></span>`;
                    }).join('') + `</div>`;
            } else {
                transHtml = `<div style="margin-top: 6px; font-size: 11px; color: var(--text-muted);">• Terminal Step (End of Path)</div>`;
            }

            const alertCount = stepInfo.wazuh_alerts ? stepInfo.wazuh_alerts.length : 0;

            stepDiv.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px dashed rgba(255,255,255,0.08); padding-bottom: 6px; margin-bottom: 6px;">
                    <strong style="color: var(--cyan); font-size: 12px; font-family: var(--font-title);">${escapeHtml(stepInfo.name || stepKey)}</strong>
                    <span class="badge badge-info" style="font-size: 9px; padding: 1px 4px;">${escapeHtml(stepInfo.mitre_technique)}</span>
                </div>
                <div style="font-size: 11px; color: var(--text-main); font-family: var(--font-mono);">Replay: ${alertCount} alert(s)</div>
                ${transHtml}
            `;
            preview.appendChild(stepDiv);
        }
    } else {
        try {
            const events = await api.get(`/simulations/scenarios/${sc.id}/events`);
            preview.innerHTML = '';
            if (events && events.length > 0) {
                events.forEach(evt => {
                    const line = document.createElement('div');
                    line.className = 'preview-line';
                    line.textContent = JSON.stringify(evt);
                    preview.appendChild(line);
                });
            } else {
                preview.innerHTML = '<div class="text-center" style="padding: 10px; color: var(--text-muted);">No events found.</div>';
            }
        } catch (err) {
            preview.innerHTML = '<div class="text-center text-error" style="padding: 10px;">Failed to load preview events.</div>';
        }
    }
}

// 2. RUNS SECTION
async function loadRuns() {
    const tbody = document.getElementById('runs-table-body');
    try {
        const runs = await api.get('/simulations/runs');
        state.runs = runs;

        if (runs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center" style="padding: 20px; color: var(--text-muted);">No simulation runs recorded.</td></tr>';
            return;
        }

        tbody.innerHTML = '';
        runs.forEach(run => {
            const tr = document.createElement('tr');
            tr.className = state.selectedRunId === run.id ? 'active-row' : '';

            const statusClass = run.status === 'COMPLETED' ? 'status-completed' :
                                run.status === 'RUNNING' ? 'status-running' : 'status-failed';

            const runDate = new Date(run.started_at || run.created_at).toLocaleString();

            let pathHtml = '';
            if (run.traversed_path && run.traversed_path.length > 0) {
                pathHtml = `<div style="margin-top: 6px; display: flex; flex-wrap: wrap; gap: 4px; align-items: center;">` + 
                    run.traversed_path.map((node, i) => {
                        const arrow = i > 0 ? '<i class="fa-solid fa-chevron-right" style="font-size: 8px; color: var(--text-muted); margin: 0 1px;"></i>' : '';
                        return `${arrow}<span class="badge badge-info" style="font-size: 9px; padding: 2px 5px; text-transform: none; font-family: var(--font-sans); font-weight: 500;">${escapeHtml(node)}</span>`;
                    }).join('') + `</div>`;
            }

            tr.innerHTML = `
                <td style="font-family: var(--font-mono); font-size: 11px;">${run.id.substring(0, 8)}...</td>
                <td style="font-weight: 500; padding-top: 8px; padding-bottom: 8px;">
                    <div>${escapeHtml(run.scenario_name)}</div>
                    ${pathHtml}
                </td>
                <td class="status-badge ${statusClass}">${escapeHtml(run.status)}</td>
                <td style="font-family: var(--font-mono);">${run.send_rate_per_sec} evt/s</td>
                <td style="color: var(--text-muted); font-size: 11px;">${runDate}</td>
            `;

            tr.addEventListener('click', () => {
                tbody.querySelectorAll('tr').forEach(r => r.classList.remove('active-row'));
                tr.classList.add('active-row');
                state.selectedRunId = run.id;
                loadRunAuditDetails(run.id);
            });

            tbody.appendChild(tr);
        });

        if (state.selectedRunId) {
            const activeRun = runs.find(r => r.id === state.selectedRunId);
            if (activeRun) loadRunAuditDetails(activeRun.id);
        }
    } catch (err) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-center text-error" style="padding: 20px;">Failed to load run history.</td></tr>';
    }
}

async function loadRunAuditDetails(runId) {
    document.getElementById('audit-empty').style.display = 'none';
    const wrap = document.getElementById('audit-table-wrap');
    wrap.style.display = 'block';

    const tbody = document.getElementById('audit-table-body');
    tbody.innerHTML = '<tr><td colspan="5" class="text-center" style="padding: 20px;"><i class="fa-solid fa-spinner fa-spin"></i> Loading details...</td></tr>';

    try {
        const data = await api.get(`/simulations/runs/${runId}/results`);
        const results = data.results || [];

        if (results.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center" style="padding: 20px; color: var(--text-muted);">No audit records found for this run.</td></tr>';
            return;
        }

        // Group results by session_id
        const sessions = {};
        results.forEach(res => {
            const sessId = res.session_id || 'no-session';
            if (!sessions[sessId]) {
                sessions[sessId] = {
                    session_id: sessId,
                    expected_playbooks: res.expected_playbooks || [],
                    actual_playbook: res.actual_playbook || 'None',
                    verdict: res.verdict || res.match_result,
                    events: []
                };
            }
            sessions[sessId].events.push(res);
        });

        tbody.innerHTML = '';
        Object.values(sessions).forEach(sess => {
            const tr = document.createElement('tr');

            const verdictClass = sess.verdict === 'TRUE_POSITIVE' ? 'text-emerald' :
                                 sess.verdict === 'FALSE_POSITIVE' ? 'text-error' : 'text-warning';

            const sessDisplay = sess.session_id !== 'no-session' ? `${sess.session_id.substring(0, 12)}...` : 'N/A';

            tr.innerHTML = `
                <td style="font-family: var(--font-mono); font-size: 11px; color: var(--cyan);">${sessDisplay}</td>
                <td style="font-weight: 500;">${escapeHtml(sess.expected_playbooks ? sess.expected_playbooks.join(', ') : 'None')}</td>
                <td>${escapeHtml(sess.actual_playbook || 'None')}</td>
                <td class="${verdictClass}" style="font-weight: bold; font-size: 11px;">${escapeHtml(sess.verdict)}</td>
                <td>
                    <button class="btn btn-secondary btn-view-events" style="padding: 2px 8px; font-size: 11px; display: flex; align-items: center; gap: 4px;">
                        <i class="fa-solid fa-list"></i> ${sess.events.length} Events
                    </button>
                </td>
            `;

            const viewBtn = tr.querySelector('.btn-view-events');
            if (viewBtn) {
                viewBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    showSessionEventsModal(sess.session_id, sess.events);
                });
            }

            tbody.appendChild(tr);
        });
    } catch (err) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-center text-error" style="padding: 20px;">Failed to load audit results.</td></tr>';
    }
}

function showSessionEventsModal(sessionId, events) {
    const modal = document.getElementById('events-modal');
    const modalSessionId = document.getElementById('modal-session-id');
    const tbody = document.getElementById('modal-events-tbody');

    if (!modal || !tbody) return;

    modalSessionId.textContent = sessionId !== 'no-session' ? sessionId : 'N/A (No active session)';
    tbody.innerHTML = '';

    // Sort events by sequence_order or created_at
    const sortedEvents = [...events].sort((a, b) => {
        if (a.sequence_order !== null && b.sequence_order !== null) {
            return a.sequence_order - b.sequence_order;
        }
        return new Date(a.created_at) - new Date(b.created_at);
    });

    sortedEvents.forEach(evt => {
        const tr = document.createElement('tr');
        const seq = evt.sequence_order !== undefined && evt.sequence_order !== null ? evt.sequence_order : '-';
        const technique = evt.mitre_technique || (evt.expected_mitre ? evt.expected_mitre.join(', ') : 'None');
        const respTime = evt.response_time_ms ? `${evt.response_time_ms} ms` : '-';
        const dateStr = new Date(evt.created_at).toLocaleString();

        tr.innerHTML = `
            <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">${seq}</td>
            <td style="font-weight: 500;">${escapeHtml(technique)}</td>
            <td style="font-family: var(--font-mono); font-size: 11px;">${respTime}</td>
            <td style="color: var(--text-muted); font-size: 11px;">${dateStr}</td>
        `;
        tbody.appendChild(tr);
    });

    modal.style.display = 'flex';
}

async function loadStats() {
    try {
        const stats = await api.get('/simulations/stats');
        state.stats = stats;

        document.getElementById('stats-accuracy').textContent = `${stats.accuracy_rate}%`;
        document.getElementById('stats-runs').textContent = stats.total_runs;
        document.getElementById('stats-matched').textContent = stats.matched;
        document.getElementById('stats-mismatched').textContent = stats.mismatched;
    } catch (err) {
        console.error('Failed to load stats:', err);
    }
}

// 3. BULK SECTION
function updateBulkControllerUI() {
    const bulkBtn = document.getElementById('bulk-execute-btn');
    if (!bulkBtn) return;

    const count = selectedBulkScenarioIds.size;
    if (count === 0) {
        bulkBtn.disabled = true;
        bulkBtn.innerHTML = '<i class="fa-solid fa-play"></i> Trigger Bulk Simulation';
    } else {
        bulkBtn.disabled = false;
        bulkBtn.innerHTML = `<i class="fa-solid fa-play"></i> Trigger Bulk Simulation (${count})`;
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

async function loadBulkScenariosList() {
    const listContainer = document.getElementById('bulk-scenario-list');
    if (!listContainer) return;
    
    try {
        const dataset = await api.get('/simulations/scenarios');
        
        if (!dataset || dataset.length === 0) {
            listContainer.innerHTML = '<div class="tree-empty">No scenarios configured in simulator database.</div>';
            return;
        }
        
        // Group scenarios by MITRE ID
        const groups = {}; // mitreId -> Array of scenarios
        
        dataset.forEach(sc => {
            if (sc.type === "dag") {
                const key = "DAG Scenarios";
                if (!groups[key]) groups[key] = [];
                groups[key].push(sc);
                return;
            }

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
        
        // Sort keys: DAG first, then alphabetically, with Other last
        const sortedKeys = Object.keys(groups).sort((a, b) => {
            if (a === "DAG Scenarios") return -1;
            if (b === "DAG Scenarios") return 1;
            if (a === "Other") return 1;
            if (b === "Other") return -1;
            return a.localeCompare(b);
        });
        
        // Populate category dropdown
        const categorySelect = document.getElementById('bulk-category-select');
        if (categorySelect) {
            categorySelect.innerHTML = '<option value="all">All Categories</option>';
            sortedKeys.forEach(techId => {
                const techName = techId === "DAG Scenarios"
                    ? "DAG / Multi-stage Scenarios"
                    : techId === "Other" 
                    ? "Other / Custom Scenarios" 
                    : `${techId} - ${MITRE_NAMES[techId] || 'MITRE Technique'}`;
                
                const opt = document.createElement('option');
                opt.value = techId;
                opt.textContent = `${techName} (${groups[techId].length})`;
                categorySelect.appendChild(opt);
            });
            
            if (!categorySelect.dataset.listenerAdded) {
                categorySelect.addEventListener('change', () => {
                    renderFilteredScenarios();
                });
                categorySelect.dataset.listenerAdded = "true";
            }
        }

        function renderFilteredScenarios() {
            listContainer.innerHTML = '';
            const selectedVal = categorySelect ? categorySelect.value : 'all';
            const keysToRender = selectedVal === 'all' ? sortedKeys : [selectedVal];
            
            keysToRender.forEach(techId => {
                const scList = groups[techId];
                if (!scList) return;
                
                const node = document.createElement('div');
                node.className = 'tree-node';
                
                const techName = techId === "DAG Scenarios"
                    ? "DAG / Multi-stage Scenarios"
                    : techId === "Other" 
                    ? "Other / Custom Scenarios" 
                    : `${techId} - ${MITRE_NAMES[techId] || 'MITRE Technique'}`;
                    
                node.innerHTML = `
                    <div class="tree-header" style="display: flex; align-items: center; gap: 8px; min-width: 0;">
                        <i class="fa-solid fa-chevron-down tree-toggle-icon" style="cursor: pointer; padding: 4px;"></i>
                        <input type="checkbox" class="bulk-group-select-checkbox" data-group-id="${escapeHtml(techId)}" style="cursor: pointer; width: 14px; height: 14px; accent-color: var(--primary);">
                        <span style="flex-grow: 1; cursor: pointer; user-select: none; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${escapeHtml(techName)} (${scList.length})</span>
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
                    toggleIcon.classList.toggle('collapsed');
                    childrenContainer.classList.toggle('hide');
                });
                
                groupCheckbox.addEventListener('change', (e) => {
                    const isChecked = e.target.checked;
                    const childCheckboxes = childrenContainer.querySelectorAll('.bulk-sc-select-checkbox');
                    childCheckboxes.forEach(cb => {
                        const scId = cb.getAttribute('data-scenario-id');
                        cb.checked = isChecked;
                        if (isChecked) {
                            selectedBulkScenarioIds.add(scId);
                        } else {
                            selectedBulkScenarioIds.delete(scId);
                        }
                    });
                    updateBulkControllerUI();
                });
                
                scList.sort((a,b) => a.name.localeCompare(b.name)).forEach(sc => {
                    const leaf = document.createElement('div');
                    leaf.className = 'tree-leaf';
                    leaf.style.paddingLeft = '32px';
                    
                    const checked = selectedBulkScenarioIds.has(sc.id) ? 'checked' : '';
                    
                    leaf.innerHTML = `
                        <label style="display: flex; align-items: center; gap: 10px; width: 100%; cursor: pointer; user-select: none; margin: 0; min-width: 0;">
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
                        
                        const allCheckboxes = childrenContainer.querySelectorAll('.bulk-sc-select-checkbox');
                        const checkedCount = Array.from(allCheckboxes).filter(cb => cb.checked).length;
                        
                        if (checkedCount === 0) {
                            groupCheckbox.checked = false;
                            groupCheckbox.indeterminate = false;
                        } else if (checkedCount === allCheckboxes.length) {
                            groupCheckbox.checked = true;
                            groupCheckbox.indeterminate = false;
                        } else {
                            groupCheckbox.checked = false;
                            groupCheckbox.indeterminate = true;
                        }
                        
                        updateBulkControllerUI();
                    });
                    
                    childrenContainer.appendChild(leaf);
                });
                
                // Initialize group checkbox state based on selection
                const allCheckboxes = childrenContainer.querySelectorAll('.bulk-sc-select-checkbox');
                if (allCheckboxes.length > 0) {
                    const checkedCount = Array.from(allCheckboxes).filter(cb => cb.checked).length;
                    if (checkedCount === 0) {
                        groupCheckbox.checked = false;
                        groupCheckbox.indeterminate = false;
                    } else if (checkedCount === allCheckboxes.length) {
                        groupCheckbox.checked = true;
                        groupCheckbox.indeterminate = false;
                    } else {
                        groupCheckbox.checked = false;
                        groupCheckbox.indeterminate = true;
                    }
                }
                
                listContainer.appendChild(node);
            });
        }

        renderFilteredScenarios();
        updateBulkControllerUI();
        
    } catch (err) {
        console.error('Failed to load scenarios list:', err);
        listContainer.innerHTML = '<div class="tree-empty text-error">Failed to load scenarios.</div>';
    }
}

async function loadBulkRuns() {
    const tbody = document.getElementById('bulk-runs-tbody');
    if (!tbody) return;
    
    try {
        const bulkRuns = await api.get('/simulations/bulk-runs');
        state.bulkRuns = bulkRuns;
        
        if (!bulkRuns || bulkRuns.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="text-center" style="padding: 20px; color: var(--text-muted);">No bulk runs recorded.</td></tr>';
            return;
        }
        
        tbody.innerHTML = '';
        bulkRuns.forEach(bulk => {
            const tr = document.createElement('tr');
            if (state.selectedBulkRunId === bulk.id) {
                tr.className = 'active-row';
            }
            
            const statusClass = bulk.status === 'COMPLETED' 
                ? 'badge-success' 
                : bulk.status === 'RUNNING' 
                ? 'badge-info' 
                : bulk.status === 'PARTIALLY_COMPLETED' 
                ? 'badge-warning' 
                : bulk.status === 'CANCELLED' 
                ? 'badge-muted' 
                : bulk.status === 'FAILED' 
                ? 'badge-error' 
                : 'badge-muted';
                
            const total = bulk.total_scenarios || 0;
            const completed = bulk.completed_scenarios || 0;
            
            // Calculate accuracy rate for completed ones
            const matched = bulk.matched_playbooks || 0;
            const mismatched = bulk.mismatched_playbooks || 0;
            const nobook = bulk.no_playbook || 0;
            const totalFinished = matched + mismatched + nobook;
            const accuracy = totalFinished > 0 ? `${Math.round((matched / totalFinished) * 100)}%` : '0%';
            const runDate = new Date(bulk.created_at).toLocaleString();
                
            tr.innerHTML = `
                <td style="font-family: var(--font-mono); font-size: 11px;">${bulk.id.substring(0, 8)}...</td>
                <td style="font-weight: 500;">${escapeHtml(bulk.name)}</td>
                <td style="font-family: var(--font-mono); font-size: 11px;">${escapeHtml(bulk.llm_model || 'Unknown')}</td>
                <td><span class="badge ${bulk.strip_labels ? 'badge-warning' : 'badge-muted'}">${bulk.strip_labels ? 'YES' : 'NO'}</span></td>
                <td><span class="badge ${statusClass}">${escapeHtml(bulk.status)} (${completed}/${total})</span></td>
                <td style="font-family: var(--font-mono); font-weight: bold; color: ${totalFinished > 0 ? 'var(--cyan)' : 'var(--text-muted)'}">${accuracy}</td>
                <td>${runDate}</td>
                <td>
                    ${bulk.status === 'RUNNING' ? `
                        <button class="btn btn-secondary cancel-bulk-btn" data-bulk-id="${bulk.id}" style="padding: 2px 6px; font-size: 9.5px; line-height: 1.2;">
                            <i class="fa-solid fa-ban"></i> Cancel
                        </button>
                    ` : ''}
                </td>
            `;
            
            const cancelBtn = tr.querySelector('.cancel-bulk-btn');
            if (cancelBtn) {
                cancelBtn.addEventListener('click', async (e) => {
                    e.stopPropagation();
                    if (confirm('Are you sure you want to cancel this bulk run?')) {
                        try {
                            cancelBtn.disabled = true;
                            cancelBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> ...';
                            await api.post(`/simulations/bulk-runs/${bulk.id}/cancel`);
                            showToast('Bulk run cancelled.', 'success');
                            await loadBulkRuns();
                        } catch (err) {
                            showToast(err.message || 'Failed to cancel bulk run', 'error');
                            cancelBtn.disabled = false;
                            cancelBtn.innerHTML = '<i class="fa-solid fa-ban"></i> Cancel';
                        }
                    }
                });
            }
            
            tr.addEventListener('click', () => {
                tbody.querySelectorAll('tr').forEach(r => r.classList.remove('active-row'));
                tr.classList.add('active-row');
                state.selectedBulkRunId = bulk.id;
                loadBulkDetails(bulk.id);
            });
            
            tbody.appendChild(tr);
        });

        if (state.selectedBulkRunId) {
            const activeBulk = bulkRuns.find(b => b.id === state.selectedBulkRunId);
            if (activeBulk) loadBulkDetails(activeBulk.id);
        }
    } catch (err) {
        console.error('Failed to load bulk runs list:', err);
    }
}

async function loadBulkDetails(bulkRunId) {
    const tbody = document.getElementById('bulk-detail-tbody');
    const nameBadge = document.getElementById('bulk-detail-name-badge');
    if (!tbody) return;
    
    document.getElementById('bulk-detail-empty').style.display = 'none';
    const wrap = document.getElementById('bulk-detail-wrap');
    wrap.style.display = 'block';
    
    tbody.innerHTML = '<tr><td colspan="7" class="text-center" style="padding: 20px;"><i class="fa-solid fa-spinner fa-spin"></i> Loading details...</td></tr>';
    
    try {
        const data = await api.get(`/simulations/bulk-runs/${bulkRunId}/results`);
        const runs = data.runs || [];
        const bulk = data.bulk_run || {};
        
        if (nameBadge) {
            nameBadge.textContent = `BULK RUN: ${bulk.name || bulkRunId}`;
            nameBadge.classList.remove('hide');
        }
        
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
                
            const sessionsCount = (run.matched_playbooks || 0) + (run.mismatched_playbooks || 0) + (run.no_playbook || 0);
            const progress = run.status === 'RUNNING' && sessionsCount === 0
                ? 'Pending'
                : `${sessionsCount} sessions`;

            let pathHtml = '';
            if (run.traversed_path && run.traversed_path.length > 0) {
                pathHtml = `<div style="margin-top: 6px; display: flex; flex-wrap: wrap; gap: 4px; align-items: center;">` + 
                    run.traversed_path.map((node, i) => {
                        const arrow = i > 0 ? '<i class="fa-solid fa-chevron-right" style="font-size: 8px; color: var(--text-muted); margin: 0 1px;"></i>' : '';
                        return `${arrow}<span class="badge badge-info" style="font-size: 9px; padding: 2px 5px; text-transform: none; font-family: var(--font-sans); font-weight: 500;">${escapeHtml(node)}</span>`;
                    }).join('') + `</div>`;
            }
                
            tr.innerHTML = `
                <td style="font-weight: 500; padding-top: 8px; padding-bottom: 8px;">
                    <div>${escapeHtml(run.scenario_name || 'Deleted Scenario')}</div>
                    ${pathHtml}
                </td>
                <td><span class="badge ${statusClass}">${escapeHtml(run.status)}</span></td>
                <td>${progress}</td>
                <td class="text-emerald" style="font-family: var(--font-mono); font-weight: bold; color: var(--success);">${run.matched_playbooks || 0}</td>
                <td class="text-error" style="font-family: var(--font-mono); font-weight: bold; color: var(--error);">${run.mismatched_playbooks || 0}</td>
                <td class="text-warning" style="font-family: var(--font-mono); font-weight: bold; color: var(--primary);">${run.no_playbook || 0}</td>
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
                    state.selectedRunId = run.id;
                    const runsNav = document.querySelector('.side-nav .nav-item[data-target="panel-runs"]');
                    if (runsNav) runsNav.click();
                });
            }
            
            tbody.appendChild(tr);
        });
    } catch (err) {
        console.error('Failed to load bulk run details:', err);
        tbody.innerHTML = '<tr><td colspan="7" class="text-center text-error" style="padding: 20px;">Failed to load bulk run details.</td></tr>';
    }
}

// Helpers
function escapeHtml(str) {
    if (!str) return '';
    return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;

    let icon = 'fa-info-circle';
    if (type === 'success') icon = 'fa-check-circle';
    if (type === 'error') icon = 'fa-exclamation-triangle';

    toast.innerHTML = `
        <i class="fa-solid ${icon}"></i>
        <span>${escapeHtml(message)}</span>
    `;

    container.appendChild(toast);

    // Fadeout after 4 seconds
    setTimeout(() => {
        toast.style.transition = 'opacity 0.5s, transform 0.5s';
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(20px)';
        setTimeout(() => toast.remove(), 500);
    }, 4000);
}
