-- Safe enum creation using a DO block
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'session_source') THEN
        CREATE TYPE session_source AS ENUM ('SIEM', 'USER', 'SYSTEM');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'session_status') THEN
        CREATE TYPE session_status AS ENUM (
            'ACTIVE',           -- Processing in progress
            'WAITING_APPROVAL', -- HITL approval required
            'COMPLETED',        -- Succeeded
            'FAILED',           -- Failed with error
            'ARCHIVED'          -- Soft-deleted/archived
        );
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'triage_verdict') THEN
        CREATE TYPE triage_verdict AS ENUM ('TRUE_POSITIVE', 'FALSE_POSITIVE', 'UNDETERMINED');
    END IF;
END$$;

-- Create main sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    deleted_at    TIMESTAMPTZ,
    display_name  VARCHAR(255) NOT NULL,
    source        session_source NOT NULL,
    status        session_status NOT NULL DEFAULT 'ACTIVE',
    owner_id      VARCHAR(255) NOT NULL DEFAULT 'anonymous',
    agent_name    VARCHAR(255),
    
    -- SIEM-specific metadata
    siem_rule_id      VARCHAR(255),
    siem_rule_desc    VARCHAR(1000),
    siem_severity     INTEGER,
    source_ip         VARCHAR(255),
    mitre_ids         TEXT[],
    verdict           triage_verdict,
    
    -- Timing
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at  TIMESTAMPTZ,
    
    -- Stats
    message_count INTEGER NOT NULL DEFAULT 0,
    tool_calls    INTEGER NOT NULL DEFAULT 0,
    hitl_count    INTEGER NOT NULL DEFAULT 0,
    
    -- Langfuse connection (optional, dev-only)
    langfuse_trace_id VARCHAR(255),
    
    -- Full alert payload
    alert_payload JSONB
);

-- Migration block to rename wazuh columns to generic siem columns if they exist in an already created table
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='sessions' AND column_name='wazuh_rule_id') THEN
        ALTER TABLE sessions RENAME COLUMN wazuh_rule_id TO siem_rule_id;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='sessions' AND column_name='wazuh_rule_desc') THEN
        ALTER TABLE sessions RENAME COLUMN wazuh_rule_desc TO siem_rule_desc;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='sessions' AND column_name='wazuh_severity') THEN
        ALTER TABLE sessions RENAME COLUMN wazuh_severity TO siem_severity;
    END IF;
END$$;

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_sessions_source ON sessions(source);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);
CREATE INDEX IF NOT EXISTS idx_sessions_owner ON sessions(owner_id);
CREATE INDEX IF NOT EXISTS idx_sessions_created ON sessions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_siem_rule ON sessions(siem_rule_id) WHERE source = 'SIEM';

-- Create session events table (Audit Trail)
CREATE TABLE IF NOT EXISTS session_events (
    id          BIGSERIAL PRIMARY KEY,
    session_id  UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    event_type  VARCHAR(100) NOT NULL,         -- 'message', 'tool_call', 'hitl_request', 'hitl_response', 'status_change', 'error', 'system'
    actor       VARCHAR(100) NOT NULL,         -- 'agent', 'user', 'system', 'siem'
    content     VARCHAR(1000),
    metadata    JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for session events order
CREATE INDEX IF NOT EXISTS idx_session_events_session ON session_events(session_id, created_at);
