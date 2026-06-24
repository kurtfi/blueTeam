-- Database Migration: Add support for DAG-based attack scenarios

-- 1. Add type and dag_structure to attack_scenarios
ALTER TABLE simulator.attack_scenarios
    ADD COLUMN IF NOT EXISTS type VARCHAR(50) NOT NULL DEFAULT 'linear',
    ADD COLUMN IF NOT EXISTS dag_structure JSONB DEFAULT NULL;

-- 2. Add traversed_path to simulation_runs to record node execution sequence
ALTER TABLE simulator.simulation_runs
    ADD COLUMN IF NOT EXISTS traversed_path TEXT[] DEFAULT NULL;
