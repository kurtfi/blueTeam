/**
 * Agentix Web UI - Playbooks Manager
 */

import * as api from './api.js';
import { escapeHtml } from './utils.js';

// DOM Elements
const playbooksListContainer = document.getElementById('playbooks-list-container');
const playbooksMarkdownViewer = document.getElementById('playbooks-markdown-viewer');

let playbooksCache = [];

export async function loadPlaybooks() {
    if (!playbooksListContainer) return;
    
    playbooksListContainer.innerHTML = `
        <div class="loading-state">
            <i class="fa-solid fa-spinner fa-spin text-cyan" aria-hidden="true"></i> Loading…
        </div>
    `;

    try {
        const playbooks = await api.getPlaybooksSummary();
        playbooksCache = playbooks || [];
        renderPlaybooksList(playbooksCache);
    } catch (err) {
        console.error("Failed to load playbooks", err);
        playbooksListContainer.innerHTML = `
            <div class="error-msg">
                <i class="fa-solid fa-triangle-exclamation"></i>
                <span>Failed: ${escapeHtml(err.message)}</span>
            </div>
        `;
    }
}

export function renderPlaybooksList(playbooks) {
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
        
        const severity = pb.severity || 'MEDIUM';
        let badgeClass = 'badge-info';
        if (severity.toUpperCase() === 'CRITICAL') badgeClass = 'badge-error';
        else if (severity.toUpperCase() === 'HIGH') badgeClass = 'badge-warning';
        else if (severity.toUpperCase() === 'LOW') badgeClass = 'badge-muted';
        
        const mitreText = pb.mitre_ids && pb.mitre_ids.length > 0 ? pb.mitre_ids.join(', ') : 'N/A';
        
        item.innerHTML = `
            <div class="playbook-item-header">
                <span class="playbook-id-badge">${escapeHtml(pb.id)}</span>
                <span class="badge ${badgeClass}">${escapeHtml(severity)}</span>
            </div>
            <div class="playbook-name">${escapeHtml(pb.name)}</div>
            <div class="playbook-meta-line">
                MITRE: ${escapeHtml(mitreText)} | Steps: ${escapeHtml(pb.steps || '0')}
            </div>
        `;
        playbooksListContainer.appendChild(item);
    });
}

export async function showPlaybookDetails(id) {
    if (!playbooksMarkdownViewer) return;

    playbooksMarkdownViewer.innerHTML = `
        <div class="loading-state">
            <i class="fa-solid fa-spinner fa-spin text-cyan" aria-hidden="true"></i> Loading Playbook Details…
        </div>
    `;

    try {
        const pb = await api.getPlaybookDetails(id);
        
        const severity = pb.severity || 'MEDIUM';
        let badgeClass = 'badge-info';
        if (severity.toUpperCase() === 'CRITICAL') badgeClass = 'badge-error';
        else if (severity.toUpperCase() === 'HIGH') badgeClass = 'badge-warning';
        else if (severity.toUpperCase() === 'LOW') badgeClass = 'badge-muted';

        const escapedId = escapeHtml(pb.id);
        const escapedName = escapeHtml(pb.name);
        const escapedDescription = escapeHtml(pb.description);
        
        const mitreTags = pb.mitre_ids 
            ? pb.mitre_ids.map(mid => `<span class="tool-chip"><i class="fa-solid fa-tag"></i> ${escapeHtml(mid)}</span>`).join(' ')
            : '<span class="text-muted">None</span>';

        let stepsHtml = '';
        if (pb.steps && pb.steps.length > 0) {
            pb.steps.forEach(step => {
                const groupClass = `group-${escapeHtml(step.group.toLowerCase())}`;
                stepsHtml += `
                    <div class="timeline-step ${step.approval ? 'step-requires-approval' : ''}">
                        <div class="timeline-step-node"></div>
                        <div class="timeline-step-content">
                            <div class="step-meta">
                                <span class="step-num-title">Step ${step.order + 1}: ${escapeHtml(step.title)}</span>
                                <span class="step-group-badge ${groupClass}">${escapeHtml(step.group)}</span>
                            </div>
                            <p class="step-description">${escapeHtml(step.description)}</p>
                            <div class="step-footer-row">
                                <span class="step-tool-hint"><i class="fa-solid fa-screwdriver-wrench"></i> ${escapeHtml(step.tool)}</span>
                                ${step.approval
                                    ? `<span class="step-approval-warning"><i class="fa-solid fa-triangle-exclamation"></i> Approval: ${escapeHtml(step.approval)}</span>`
                                    : ''
                                }
                            </div>
                        </div>
                    </div>
                `;
            });
        }

        playbooksMarkdownViewer.innerHTML = `
            <div class="playbook-detail-header">
                <h3>[${escapedId}] ${escapedName}</h3>
                <div class="playbook-detail-meta">
                    <span class="badge ${badgeClass}">${escapeHtml(severity)} Severity</span>
                    ${mitreTags}
                </div>
            </div>
            <p class="playbook-detail-desc">${escapedDescription}</p>
            <div class="timeline-title">REACTION SEQUENCE TIMELINE</div>
            <div class="playbook-timeline">
                ${stepsHtml}
            </div>
        `;
    } catch (err) {
        console.error("Failed to load playbook details", err);
        playbooksMarkdownViewer.innerHTML = `
            <div class="welcome-message">
                <i class="fa-solid fa-triangle-exclamation text-error placeholder-icon"></i>
                <p>Failed to load playbook steps for ${escapeHtml(id)}: ${escapeHtml(err.message)}</p>
            </div>
        `;
    }
}
