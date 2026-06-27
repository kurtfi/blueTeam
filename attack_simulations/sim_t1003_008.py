#!/usr/bin/env python3
"""
Simulate T1003.008 - OS Credential Dumping: /etc/shadow Access
"""

from utils import LOG_FILE, SimulationRunner, timestamp, write_log_entry


def simulate_t1003_008():
    ts = timestamp()

    log_entry = (
        f"{ts} wazuh-manager syslog: "
        f"MITRE-ATTACK-SIM: T1003.008 "
        f"user=www-data pid=31337 "
        f"cmd=cat-etc-shadow "
        f"file=/etc/shadow action=READ severity=CRITICAL "
        f"src_ip=10.10.10.99"
    )

    ok, err = write_log_entry(log_entry)

    if ok:
        print(f"  \u2713 Log entry written to {LOG_FILE}")
        print(f"  \u2192 Entry: {log_entry[:120]}")
        print("  \u2192 Expected Wazuh rule: 100002 (level 10)")
        print("  \u2192 Expected MITRE tag: T1003.008 - OS Credential Dumping")
        return True
    else:
        print(f"  \u2717 Failed to write log: {err}")
        return False


if __name__ == "__main__":
    runner = SimulationRunner(
        name="T1003.008", description="OS Credential Dumping (/etc/shadow access)", expected_rules=["100002"]
    )
    runner.run(simulate_t1003_008)
