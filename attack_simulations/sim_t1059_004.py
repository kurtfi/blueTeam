#!/usr/bin/env python3
"""
Simulate T1059.004 - Command and Scripting Interpreter: Unix Shell / Reverse Shell
"""

from utils import LOG_FILE, SimulationRunner, timestamp, write_log_entry


def simulate_t1059_004():
    ts = timestamp()

    log_entry = (
        f"{ts} wazuh-manager syslog: "
        f"MITRE-ATTACK-SIM: T1059.004 "
        f"user=nginx pid=4444 "
        f"cmd=bash-reverse-shell "
        f"shell=/bin/bash direction=outbound "
        f"dst_ip=10.10.10.99 dst_port=4444 "
        f"action=EXECUTE severity=CRITICAL"
    )

    ok, err = write_log_entry(log_entry)

    if ok:
        print(f"  \u2713 Log entry written to {LOG_FILE}")
        print(f"  \u2192 Entry: {log_entry[:120]}")
        print("  \u2192 Expected Wazuh rule: 100003 (level 10)")
        print("  \u2192 Expected MITRE tag: T1059.004 - Command Execution")
        return True
    else:
        print(f"  \u2717 Failed to write log: {err}")
        return False


if __name__ == "__main__":
    runner = SimulationRunner(
        name="T1059.004",
        description="Command and Scripting Interpreter: Unix Shell / Reverse Shell",
        expected_rules=["100003"]
    )
    runner.run(simulate_t1059_004)

