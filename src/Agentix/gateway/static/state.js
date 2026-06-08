/**
 * Agentix Web UI - Pub/Sub State Store
 */

class StateStore {
    constructor() {
        this.state = {
            activeSessionId: null,
            activeAgent: 'soc_analyst',
            isStreaming: false,
            processingSessions: new Set(),
            dashboardPage: 1,
            dashboardPageSize: 20,
            dashboardSessionsList: [],
            dashboardTotalCount: 0,
            sessionsPage: 1,
            sessionsPageSize: 20,
            sessionsFullList: [],
            sessionsTotalCount: 0,
            hitlPage: 1,
            hitlPageSize: 20,
            hitlFullList: [],
            hitlTotalCount: 0,
            activeView: ''
        };
        this.listeners = [];
    }

    subscribe(listener) {
        this.listeners.push(listener);
        return () => {
            this.listeners = this.listeners.filter(l => l !== listener);
        };
    }

    setState(changes) {
        const prevState = { ...this.state };
        
        // Handle Set objects correctly to avoid reference copying issues
        const updatedState = { ...this.state, ...changes };
        if (changes.processingSessions) {
            updatedState.processingSessions = new Set(changes.processingSessions);
        }
        
        this.state = updatedState;
        this.listeners.forEach(listener => listener(this.state, prevState));
    }

    getState() {
        return this.state;
    }
}

export const store = new StateStore();
