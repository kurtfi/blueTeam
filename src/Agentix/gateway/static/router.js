/**
 * Agentix Web UI - Yönlendirici (Router)
 */

import { store } from './state.js';

const navItems = {
    dashboard: document.getElementById('nav-dashboard'),
    sessions: document.getElementById('nav-sessions'),
    hitl: document.getElementById('nav-hitl'),
    personas: document.getElementById('nav-personas'),
    playbooks: document.getElementById('nav-playbooks'),
    simulations: document.getElementById('nav-simulations'),
    settings: document.getElementById('nav-settings')
};

const panels = {
    dashboard: document.getElementById('panel-dashboard'),
    sessions: document.getElementById('panel-sessions'),
    hitl: document.getElementById('panel-hitl'),
    'session-detail': document.getElementById('panel-session-detail'),
    personas: document.getElementById('panel-personas'),
    playbooks: document.getElementById('panel-playbooks'),
    simulations: document.getElementById('panel-simulations'),
    settings: document.getElementById('panel-settings')
};

const viewTitle = document.getElementById('view-title');
const viewDesc = document.getElementById('view-desc');
const sessionControls = document.getElementById('session-controls');

const viewMeta = {
    dashboard: {
        title: "Security Orchestration Console",
        desc: "Real-time autonomous incident investigation & threat enrichment",
        showControls: true
    },
    sessions: {
        title: "Incident Triage Sessions",
        desc: "Monitor, filter, and review active and historic agent investigations",
        showControls: false
    },
    hitl: {
        title: "Human-in-the-Loop Queue",
        desc: "Authorize or reject containment actions requested by autonomous workflows",
        showControls: false
    },
    'session-detail': {
        title: "Incident Triage Detail",
        desc: "Detailed analysis of investigation session...",
        showControls: false
    },
    personas: {
        title: "Agent Personas Registry",
        desc: "Configure, switch, and view capabilities of active security agent personas",
        showControls: false
    },
    playbooks: {
        title: "Incident Response Playbooks",
        desc: "Browse mapped incident triage checklists and response procedures",
        showControls: false
    },
    settings: {
        title: "System Configurations",
        desc: "Manage endpoint connections, storage quotas, and security logging settings",
        showControls: false
    },
    simulations: {
        title: "Attack Simulation Panel",
        desc: "Standalone SecOps alert generator, coverage analysis, and playbook accuracy benchmarking",
        showControls: false
    }
};

export function switchView(viewName) {
    store.setState({ activeView: viewName });
}

// Subscribe to state view changes to update DOM presentation
store.subscribe((state, prevState) => {
    if (state.activeView !== prevState.activeView) {
        const viewName = state.activeView;
        
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

        // Update headers & controls
        const meta = viewMeta[viewName];
        if (meta) {
            viewTitle.textContent = meta.title;
            if (viewName === 'session-detail' && state.activeSessionId) {
                viewDesc.textContent = `Detailed analysis of investigation session ${state.activeSessionId}`;
            } else {
                viewDesc.textContent = meta.desc;
            }
            
            if (meta.showControls) {
                sessionControls.classList.remove('hide');
            } else {
                sessionControls.classList.add('hide');
            }
        }
    }
});
