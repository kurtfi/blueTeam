#!/usr/import/env python3
"""
Simulate T1003.008 - OS Credential Dumping: /etc/shadow Access
"""

import sys
import time
from utils import ensure_log_file, timestamp, write_log_entry, LOG_FILE, verify_log_contents, verify_wazuh_alerts

def simulate_t1003_008():
    print("\n[T1003.008] Simulating OS Credential Dumping (/etc/shadow access)...")
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
        print(f"  \u2192 Expected Wazuh rule: 100002 (level 10)")
        print(f"  \u2192 Expected MITRE tag: T1003.008 - OS Credential Dumping")
        return True
    else:
        print(f"  \u2717 Failed to write log: {err}")
        return False

if __name__ == "__main__":
    ensure_log_file()
    if simulate_t1003_008():
        verify_log_contents()
        if "--verify" in sys.argv:
            print("\n  Waiting 5s for Wazuh to process logs...")
            time.sleep(5)
            verify_wazuh_alerts(["100002"])
