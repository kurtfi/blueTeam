-- Alter expected_playbook column type to TEXT to prevent truncation errors when returning multiple candidates
ALTER TABLE simulation_results ALTER COLUMN expected_playbook TYPE TEXT;
