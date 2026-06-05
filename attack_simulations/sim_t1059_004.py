#!/usr/import/env python3
"""
Simulate T1059.004 - Command and Scripting Interpreter: Unix Shell / Reverse Shell
"""

import sys
import time

from utils import LOG_FILE, ensure_log_file, timestamp, verify_log_contents, verify_wazuh_alerts, write_log_entry


def simulate_t1059_004():
    print("\n[T1059.004] Simulating Suspicious Command Execution (Reverse Shell)...")
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
    ensure_log_file()
    if simulate_t1059_004():
        verify_log_contents()
        if "--verify" in sys.argv:
            print("\n  Waiting 5s for Wazuh to process logs...")
            time.sleep(5)
            verify_wazuh_alerts(["100003"])
