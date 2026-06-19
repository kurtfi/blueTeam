-- AttackSimulator Database Tables

-- Saldırı senaryosu tanımları
CREATE TABLE IF NOT EXISTS attack_scenarios (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    description     VARCHAR(1000),
    mitre_ids       TEXT[],           -- Senaryodaki tüm teknikler
    source_dataset  VARCHAR(100),             -- 'mordor', 'custom', 'cremev2'
    source_path     VARCHAR(1000),             -- Orijinal dosya yolu/URL
    total_events    INT DEFAULT 0,
    status          VARCHAR(20) NOT NULL DEFAULT 'passive' CHECK (status IN ('active', 'passive')), -- 'active' veya 'passive'
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- İşlenmiş attack event kayıtları (Korelasyon motoru çıktısı → Wazuh alert)
CREATE TABLE IF NOT EXISTS attack_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scenario_id     UUID REFERENCES attack_scenarios(id) ON DELETE CASCADE,
    sequence_order  INT NOT NULL,
    mitre_technique VARCHAR(255) NOT NULL,     -- T1003.008
    mitre_tactic    VARCHAR(255),              -- Credential Access
    correlation_type VARCHAR(255) DEFAULT 'direct',  -- 'direct' (1:1) veya 'aggregation' (N:1)
    raw_event_count INT DEFAULT 1,     -- Kaç ham event'tan üretildi (brute force: 10, cred dump: 1)
    correlation_rule VARCHAR(1000),             -- Kullanılan korelasyon kuralı adı
    wazuh_alert     JSONB NOT NULL,    -- Korelasyon sonrası üretilen Wazuh alert payload
    raw_log_hash    VARCHAR(255),              -- Kaynak logun/logların SHA256'sı (dedup için)
    status          VARCHAR(20) NOT NULL DEFAULT 'passive' CHECK (status IN ('active', 'passive')), -- 'active' veya 'passive'
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Simülasyon çalıştırma kayıtları
CREATE TABLE IF NOT EXISTS simulation_runs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scenario_id     UUID REFERENCES attack_scenarios(id) ON DELETE SET NULL,
    status          VARCHAR(50) DEFAULT 'PENDING',  -- PENDING, RUNNING, COMPLETED, FAILED
    total_events    INT DEFAULT 0,
    sent_events     INT DEFAULT 0,
    matched_playbooks INT DEFAULT 0,
    mismatched_playbooks INT DEFAULT 0,
    no_playbook     INT DEFAULT 0,
    send_rate_per_sec FLOAT DEFAULT 1.0,    -- Gönderim hızı
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Her gönderilen event'ın sonucu
CREATE TABLE IF NOT EXISTS simulation_results (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id          UUID REFERENCES simulation_runs(id) ON DELETE CASCADE,
    event_id        UUID REFERENCES attack_events(id) ON DELETE SET NULL,
    session_id      VARCHAR(255),                   -- Webhook'un döndürdüğü session_id
    expected_mitre  TEXT[],
    actual_playbook VARCHAR(255),                   -- Agent'ın seçtiği playbook ID
    expected_playbook TEXT,                         -- Beklenen playbook ID (varsa)
    match_result    VARCHAR(100),                   -- CORRECT, WRONG, NO_PLAYBOOK, PENDING
    response_time_ms INT,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_attack_events_scenario ON attack_events(scenario_id);
CREATE INDEX IF NOT EXISTS idx_simulation_results_run ON simulation_results(run_id);
CREATE INDEX IF NOT EXISTS idx_simulation_results_match ON simulation_results(match_result);
CREATE UNIQUE INDEX IF NOT EXISTS idx_only_one_active_scenario ON attack_scenarios(status) WHERE status = 'active';
