-- Toplu çalıştırma (bulk run) tablosu
CREATE TABLE IF NOT EXISTS simulation_bulk_runs (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                  VARCHAR(255) NOT NULL,
    llm_provider          VARCHAR(50),        -- 'ollama', 'openai', 'gemini'
    llm_model             VARCHAR(255),       -- 'qwen3.5:9b', 'gemma4:4b' vb.
    strip_labels          BOOLEAN DEFAULT FALSE,
    send_rate_per_sec     FLOAT DEFAULT 1.0,
    status                VARCHAR(50) DEFAULT 'RUNNING',  -- RUNNING, COMPLETED, FAILED
    total_scenarios       INT DEFAULT 0,
    completed_scenarios   INT DEFAULT 0,
    matched_playbooks     INT DEFAULT 0,
    mismatched_playbooks  INT DEFAULT 0,
    no_playbook           INT DEFAULT 0,
    created_at            TIMESTAMPTZ DEFAULT NOW(),
    completed_at          TIMESTAMPTZ
);

-- Mevcut simulation_runs tablosuna bulk_run_id FK sütunu ekle
ALTER TABLE simulation_runs
    ADD COLUMN IF NOT EXISTS bulk_run_id UUID REFERENCES simulation_bulk_runs(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_simulation_runs_bulk ON simulation_runs(bulk_run_id);
