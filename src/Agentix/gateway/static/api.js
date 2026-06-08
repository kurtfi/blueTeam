/**
 * Agentix Web UI - API Client
 */

export async function getMe() {
    const response = await fetch('/web/me');
    if (!response.ok) throw new Error('Unauthorized');
    return response.json();
}

export async function login(username, password) {
    const response = await fetch('/web/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    });
    if (!response.ok) {
        const errData = await response.json();
        throw new Error(errData.detail || 'Authentication failed');
    }
    return response.json();
}

export async function logout() {
    const response = await fetch('/web/logout', { method: 'POST' });
    if (!response.ok) throw new Error('Failed to logout');
    return response.json();
}

export async function getSessionStats() {
    const res = await fetch('/web/sessions/stats');
    if (!res.ok) throw new Error('Failed to load stats');
    return res.json();
}

export async function getSessions({ limit, offset, source, status, search }) {
    let queryParams = [];
    if (source) queryParams.push(`source=${source}`);
    if (status) queryParams.push(`status_filter=${status}`);
    if (search) queryParams.push(`search=${encodeURIComponent(search)}`);
    queryParams.push(`limit=${limit}`);
    queryParams.push(`offset=${offset}`);
    
    const url = `/web/sessions?${queryParams.join('&')}`;
    const res = await fetch(url);
    if (!res.ok) throw new Error('Failed to fetch sessions');
    const data = await res.json();
    return {
        sessions: data.sessions || [],
        total_count: data.total_count || 0
    };
}

export async function getSessionDetails(sessionId) {
    const res = await fetch(`/web/sessions/${sessionId}`);
    if (!res.ok) throw new Error(`Failed to load session metadata: ${res.status}`);
    return res.json();
}

export async function getSessionEvents(sessionId) {
    const res = await fetch(`/web/sessions/${sessionId}/events`);
    if (!res.ok) throw new Error(`Failed to load session events: ${res.status}`);
    return res.json();
}

export async function getSessionWorkspace(sessionId) {
    const res = await fetch(`/web/sessions/${sessionId}/workspace`);
    if (!res.ok) throw new Error(`Failed to load session workspace: ${res.status}`);
    return res.json();
}

export async function createSession() {
    const response = await fetch('/web/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    });
    if (!response.ok) throw new Error('Failed to create session');
    return response.json();
}

export async function getAgents() {
    const response = await fetch('/web/agents');
    if (!response.ok) throw new Error('Failed to load agents');
    return response.json();
}

export async function getPlaybooksSummary() {
    const response = await fetch('/web/playbooks/summary');
    if (!response.ok) throw new Error('Failed to load playbooks summary');
    return response.json();
}

export async function getPlaybookDetails(playbookId) {
    const response = await fetch(`/web/playbooks/${playbookId}`);
    if (!response.ok) throw new Error('Failed to load playbook details');
    return response.json();
}

export async function postHitlAction(sessionId, action) {
    const response = await fetch(`/web/sessions/${sessionId}/${action}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    });
    if (!response.ok) throw new Error(`Failed to submit HITL action: ${response.status}`);
    return response.json();
}

export async function startChatStream(sessionId, message, agent) {
    const payload = { message, session_id: sessionId };
    if (agent) payload.agent = agent;
    const response = await fetch('/web/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });
    if (!response.ok) throw new Error(`Chat API error: ${response.status}`);
    return response;
}
