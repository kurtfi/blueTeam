# Wazuh Attack Simulations Guide

This guide explains how to use the separated MITRE ATT&CK simulation scripts located in the `attack_simulations/` directory. These scripts are designed to help you verify your Wazuh detection rules, Agentix webhook integrations, and case management in TheHive.

## Available Attack Simulations

We currently support simulating 5 different MITRE ATT&CK techniques. Each simulation is isolated into its own script for easier testing and learning.

| Script Name | MITRE Technique | Description | Expected Wazuh Rule |
|-------------|-----------------|-------------|----------------------|
| `sim_t1003_008.py` | T1003.008 | OS Credential Dumping (/etc/shadow access) | 100002 |
| `sim_t1059_004.py` | T1059.004 | Reverse Shell Execution | 100003 |
| `sim_t1110.py` | T1110 | SSH Brute Force Login | 5710 / 5712 |
| `sim_t1548_001.py` | T1548.001 | SUID/SGID Privilege Escalation Abuse | syscheck / custom |
| `sim_t1048.py` | T1048 | DNS Exfiltration Tunneling | network anomaly |

## How to Run Simulations

You can run any of these simulations using `uv` or directly with python.

### 1. Basic Execution
To simply generate the logs and push them to the `wazuh-manager` container:

```bash
uv run python attack_simulations/sim_t1003_008.py
```

### 2. Execution with Verification
If you want the script to automatically query the Wazuh API to verify that the corresponding alerts were generated, append the `--verify` flag:

```bash
uv run python attack_simulations/sim_t1059_004.py --verify
```

## How to Verify Alerts Manually

After running a simulation, follow these steps to manually verify the full incident response lifecycle:

1. **Wazuh Dashboard** (`http://localhost:5601`)
   - Go to Security Events.
   - Search for the specific `rule.id` associated with the attack (e.g., `rule.id: 100002`).
   - Alerts usually appear within 30-60 seconds.

2. **SOAR Webhooks / Agentix**
   - Verify that Wazuh forwarded the alert via integrations.
   - Check your middleware logs to ensure the AI triage was triggered.

3. **TheHive** (`http://localhost:9000`)
   - Go to the **Cases** tab.
   - Look for newly created cases tagged with `[AGENTIX-SIM]` and the specific MITRE technique (e.g., `T1003.008`).

4. **Cortex** (`http://localhost:9001`)
   - Go to the **Jobs** tab to verify that the automated analyzers (e.g., VirusTotal) executed successfully.

## Extending the Simulations

If you want to add new attack scenarios:
1. Create a new file in `attack_simulations/` named `sim_<technique>.py`.
2. Import the common functions from `utils.py`:
   ```python
   from utils import ensure_log_file, timestamp, write_log_entry, verify_log_contents
   ```
3. Implement your custom logic to generate the specific syslog format required by your Wazuh decoders.
