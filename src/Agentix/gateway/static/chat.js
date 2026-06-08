/**
 * Agentix Web UI - Chat, Timeline & HITL Details
 */

import { store } from './state.js';
import * as api from './api.js';
import { 
    escapeHtml, 
    formatDate, 
    formatMarkdownToHtml, 
    showNotification, 
    fetchWithLoader, 
    getFriendlyToolName, 
    renderFriendlyParams 
} from './utils.js';
import { switchView } from './router.js';

// Local Chat Module State
let showAllEvents = false;

// DOM Elements
const chatInput = document.getElementById('detail-chat-input');
const chatMessagesContainer = document.getElementById('detail-timeline');
const thinkingIndicator = document.getElementById('thinking-indicator');

const detailDisplayName = document.getElementById('detail-display-name');
const detailSourceBadge = document.getElementById('detail-source-badge');
const detailStatusBadge = document.getElementById('detail-status-badge');
const detailVerdictBadge = document.getElementById('detail-verdict-badge');
const detailTimeBadge = document.getElementById('detail-time-badge');
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

export function scrollTerminal() {
    if (chatMessagesContainer) {
        chatMessagesContainer.scrollTop = chatMessagesContainer.scrollHeight;
    }
}

export async function renderWorkspaceFilesList(sessionId) {
    if (!detailWorkspaceFiles) return;
    try {
        const data = await api.getSessionWorkspace(sessionId);
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
                <span>${escapeHtml(f.name)} <span class="text-xs text-muted">(${escapeHtml(f.size)})</span></span>
            `;
            detailWorkspaceFiles.appendChild(item);
        });
    } catch (err) {
        console.error('Failed to load workspace files:', err);
    }
}

export function renderTimelineEvents(events) {
    if (!chatMessagesContainer) return;
    chatMessagesContainer.innerHTML = '';
    
    if (!events || events.length === 0) {
        chatMessagesContainer.innerHTML = `<div class="system-message"><p class="welcome-title">[ NO EVENTS LOGGED ]</p><p class="welcome-text">This session has no recorded audit log events.</p></div>`;
        return;
    }

    // DOM Bloat Mitigation: Truncate events if they exceed 50 items unless showAllEvents is true
    const hasMore = events.length > 50;
    if (hasMore && !showAllEvents) {
        const showMoreBtn = document.createElement('div');
        showMoreBtn.className = 'system-message';
        showMoreBtn.innerHTML = `
            <button class="btn btn-secondary btn-xs-padding" id="btn-load-more-events" style="margin: 10px auto; display: block;">
                <i class="fa-solid fa-clock-rotate-left"></i> Show earlier history (${events.length - 50} events hidden)
            </button>
        `;
        chatMessagesContainer.appendChild(showMoreBtn);
        showMoreBtn.querySelector('#btn-load-more-events').addEventListener('click', () => {
            showAllEvents = true;
            renderTimelineEvents(events);
        });
    }

    const visibleEvents = (hasMore && !showAllEvents) ? events.slice(-50) : events;
    
    visibleEvents.forEach(step => {
        const stepBlock = document.createElement('div');
        stepBlock.className = 'step-block';
        
        let headerHtml = '';
        let contentHtml = '';
        
        switch (step.event_type) {
            case 'think':
                stepBlock.classList.add('step-thinking');
                headerHtml = `<div class="step-type-header step-thinking"><i class="fa-solid fa-brain"></i> THINKING (${escapeHtml(step.actor)})</div>`;
                contentHtml = `<div class="step-content text-cyan">${escapeHtml(step.content)}</div>`;
                break;
                
            case 'tool':
            case 'act':
                stepBlock.classList.add('step-tool');
                const toolName = step.metadata?.tool_name || 'system';
                headerHtml = `<div class="step-type-header step-tool"><i class="fa-solid fa-screwdriver-wrench"></i> EXECUTING TOOL: ${escapeHtml(toolName)}</div>`;
                let inputArgs = '';
                try {
                    const inp = step.metadata?.tool_input || step.content;
                    inputArgs = typeof inp === 'string' ? inp : JSON.stringify(inp, null, 2);
                } catch (e) { inputArgs = step.content; }
                contentHtml = `<div class="step-content"><pre><code>${escapeHtml(inputArgs)}</code></pre></div>`;
                break;
                
            case 'observe':
                stepBlock.classList.add('step-observation');
                headerHtml = `<div class="step-type-header step-observation"><i class="fa-solid fa-eye"></i> OBSERVATION</div>`;
                let outputText = '';
                try {
                    const out = step.metadata?.tool_output || step.content;
                    outputText = typeof out === 'string' ? out : JSON.stringify(out, null, 2);
                } catch (e) { outputText = step.content; }
                contentHtml = `<div class="step-content"><pre><code>${escapeHtml(outputText)}</code></pre></div>`;
                break;
                
            case 'answer':
            case 'message':
                if (step.actor === 'user') {
                    const userDiv = document.createElement('div');
                    userDiv.className = 'user-msg';
                    userDiv.textContent = step.content;
                    chatMessagesContainer.appendChild(userDiv);
                    return;
                } else {
                    stepBlock.classList.add('step-answer');
                    headerHtml = `<div class="step-type-header step-answer"><i class="fa-solid fa-circle-check"></i> AGENT MESSAGE</div>`;
                    contentHtml = `<div class="step-content step-answer"><div class="step-content-inner">${escapeHtml(step.content)}</div></div>`;
                }
                break;
                
            case 'status_change':
                headerHtml = `<div class="step-type-header text-cyan"><i class="fa-solid fa-arrows-rotate"></i> AUDIT EVENT: STATUS CHANGED</div>`;
                contentHtml = `<div class="step-content text-muted">${escapeHtml(step.content)}</div>`;
                break;
                
            default:
                headerHtml = `<div class="step-type-header text-muted"><i class="fa-solid fa-clock"></i> EVENT: ${escapeHtml(step.event_type.toUpperCase())}</div>`;
                contentHtml = `<div class="step-content">${escapeHtml(step.content || '')}</div>`;
        }
        
        stepBlock.innerHTML = headerHtml + contentHtml;
        chatMessagesContainer.appendChild(stepBlock);
    });
    
    scrollTerminal();
}

export function renderSessionDetails(sess, events) {
    switchView('session-detail');

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
                chip.innerHTML = `<i class="fa-solid fa-tag"></i> ${escapeHtml(mid)}`;
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
        
        detailChatForm.onsubmit = (e) => {
            e.preventDefault();
            const msg = chatInput.value.trim();
            if (!msg || store.getState().isStreaming) return;
            
            chatInput.value = '';
            sendPrompt(msg);
        };
    }

    renderTimelineEvents(events);
}

export async function openSessionDetail(sessionId) {
    try {
        showAllEvents = false; // Reset log expansion on new session open
        store.setState({ activeSessionId: sessionId });
        
        const sess = await api.getSessionDetails(sessionId);
        const events = await api.getSessionEvents(sessionId);
        
        renderSessionDetails(sess, events);
    } catch (err) {
        console.error('Failed to open session detail view:', err);
    }
}

export async function sendPrompt(messageText) {
    const state = store.getState();
    if (state.isStreaming || !state.activeSessionId) return;
    
    store.setState({ isStreaming: true });
    
    const userDiv = document.createElement('div');
    userDiv.className = 'user-msg';
    userDiv.textContent = messageText;
    chatMessagesContainer.appendChild(userDiv);
    scrollTerminal();
    
    thinkingIndicator.classList.remove('hide');
    
    try {
        const response = await api.startChatStream(state.activeSessionId, messageText, state.activeAgent);
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
                        store.setState({ isStreaming: false });
                        thinkingIndicator.classList.add('hide');
                        await openSessionDetail(state.activeSessionId);
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
        store.setState({ isStreaming: false });
        thinkingIndicator.classList.add('hide');
        await openSessionDetail(state.activeSessionId);
    }
}

export function handleLiveStep(step) {
    thinkingIndicator.classList.add('hide');
    
    const stepBlock = document.createElement('div');
    stepBlock.className = 'step-block';
    
    let headerHtml = '';
    let contentHtml = '';
    
    switch (step.type) {
        case 'thought':
            headerHtml = `<div class="step-type-header step-thinking"><i class="fa-solid fa-brain"></i> THINKING</div>`;
            contentHtml = `<div class="step-content text-cyan">${escapeHtml(step.content)}</div>`;
            break;
            
        case 'tool':
            headerHtml = `<div class="step-type-header step-tool"><i class="fa-solid fa-screwdriver-wrench"></i> EXECUTING TOOL: ${escapeHtml(step.tool || 'system')}</div>`;
            let inputArgs = '';
            try {
                inputArgs = typeof step.tool_input === 'string' ? step.tool_input : JSON.stringify(step.tool_input, null, 2);
            } catch (e) { inputArgs = step.tool_input; }
            contentHtml = `<div class="step-content"><pre><code>${escapeHtml(inputArgs)}</code></pre></div>`;
            break;
            
        case 'observation':
            headerHtml = `<div class="step-type-header step-observation"><i class="fa-solid fa-eye"></i> OBSERVATION</div>`;
            let outputText = '';
            try {
                outputText = typeof step.tool_output === 'string' ? step.tool_output : JSON.stringify(step.tool_output, null, 2);
            } catch (e) { outputText = step.tool_output; }
            contentHtml = `<div class="step-content"><pre><code>${escapeHtml(outputText)}</code></pre></div>`;
            break;
            
        case 'answer':
            headerHtml = `<div class="step-type-header step-answer"><i class="fa-solid fa-circle-check"></i> PROCESS COMPLETE</div>`;
            contentHtml = `<div class="step-content step-answer"><div class="step-content-inner">${escapeHtml(step.content)}</div></div>`;
            renderWorkspaceFilesList(store.getState().activeSessionId);
            break;
            
        default:
            contentHtml = `<div class="step-content">${escapeHtml(step.content || '')}</div>`;
    }
    
    stepBlock.innerHTML = headerHtml + contentHtml;
    chatMessagesContainer.appendChild(stepBlock);
    scrollTerminal();
}

export async function submitHitlAction(sessionId, action) {
    const state = store.getState();
    if (state.processingSessions.has(sessionId)) return;
    
    const newProcessing = new Set(state.processingSessions);
    newProcessing.add(sessionId);
    store.setState({ processingSessions: newProcessing });

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
        const panelDetail = document.getElementById('panel-session-detail');
        
        if (panelDetail.classList.contains('active-panel') && state.activeSessionId === sessionId) {
            if (detailHitlCard) {
                detailHitlCard.classList.add('hide');
            }
            await sendPrompt(msg);
        } else {
            await api.postHitlAction(sessionId, action);
        }
    } catch (err) {
        console.error('Failed to submit HITL action:', err);
    } finally {
        const updatedProcessing = new Set(store.getState().processingSessions);
        updatedProcessing.delete(sessionId);
        store.setState({ processingSessions: updatedProcessing });
        
        // Trigger page reloads depending on view context
        const view = store.getState().activeView;
        // Since app.js controls trigger logic for pages, we can publish event or manually dispatch updates.
        // To be safe, we will let bootstrap event triggers reload the active view via state listener!
        // We'll update the state with a dummy reload toggle or simply trigger the loading in app.js
        const event = new CustomEvent('hitl-action-complete', { detail: { sessionId, action } });
        document.dispatchEvent(event);
    }
}
