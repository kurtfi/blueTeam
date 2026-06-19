-- Create agents table
CREATE TABLE IF NOT EXISTS agents (
    id VARCHAR(255) PRIMARY KEY,
    config_path VARCHAR(512) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create playbooks table
CREATE TABLE IF NOT EXISTS playbooks (
    id VARCHAR(255) PRIMARY KEY,
    file_path VARCHAR(512) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create agent_playbooks relationship table
CREATE TABLE IF NOT EXISTS agent_playbooks (
    agent_id VARCHAR(255) REFERENCES agents(id) ON DELETE CASCADE,
    playbook_id VARCHAR(255) REFERENCES playbooks(id) ON DELETE CASCADE,
    PRIMARY KEY (agent_id, playbook_id)
);
