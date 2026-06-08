/**
 * Agentix Web UI - General Utility Helpers
 */

export const FRIENDLY_TOOLS = {
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

export function getFriendlyToolName(toolName) {
    return FRIENDLY_TOOLS[toolName]?.title || toolName;
}

// HTML escaping helper for XSS prevention
export function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

export function formatDate(isoStr) {
    if (!isoStr) return '';
    try {
        const d = new Date(isoStr);
        return d.toLocaleDateString('en-US', { month: 'short', day: '2-digit' }) + ' ' + 
               d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
    } catch(e) {
        return isoStr;
    }
}

export function debounce(func, wait) {
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

export function formatMarkdownToHtml(markdown) {
    if (!markdown) return '';
    // Escape HTML first to prevent XSS
    let escaped = escapeHtml(markdown);
    
    // Replace bold text: **text** -> <strong>text</strong>
    escaped = escaped.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    
    // Replace bullet points: - item -> <li>item</li> (wrapped in ul)
    const lines = escaped.split('\n');
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
    let html = lines.join('\n');
    html = html.replace(/\n/g, '<br>');
    
    // Clean up double <br> around lists
    html = html.replace(/<\/ul><br>/g, '</ul>');
    html = html.replace(/<br><ul/g, '<ul');
    
    return html;
}

// Senior UI Floating Toast System
export function showNotification(message, type = 'success') {
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
export async function fetchWithLoader(loaderOptions, fetchFn) {
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

export function renderFriendlyParams(toolName, toolArgs, alertPayload) {
    if (!toolArgs || typeof toolArgs !== 'object') {
        return `<div class="param-item"><span class="param-label">Arguments:</span> <span class="param-value">${escapeHtml(toolArgs)}</span></div>`;
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
                    <strong class="param-value" style="color: var(--warning); font-family: var(--font-mono);">${escapeHtml(agentName || hostname)}</strong>
                </div>
            `;
        }
        if (srcIp) {
            html += `
                <div class="param-item" style="display: flex; justify-content: space-between; font-size: 12.5px; margin-bottom: 6px; border-bottom: 1px dashed rgba(245, 158, 11, 0.1); padding-bottom: 4px;">
                    <span class="param-label" style="color: var(--text-muted);"><i class="fa-solid fa-network-wired"></i> Origin/Triggering IP:</span>
                    <strong class="param-value" style="color: var(--text-bright); font-family: var(--font-mono);">${escapeHtml(srcIp)}</strong>
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
                    <span class="param-label" style="color: var(--text-muted);">${escapeHtml(label)}:</span>
                    <strong class="param-value" style="font-family: var(--font-mono); color: var(--warning);">${escapeHtml(val)}</strong>
                </div>
            `;
        }).join('');
    } else {
        html += `<div class="param-item"><span class="param-label">Parameters:</span> <span class="param-value">None</span></div>`;
    }
    
    return html;
}
