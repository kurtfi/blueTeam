#!/usr/import/env python3
"""
Simulate T1110 - Brute Force / Password Spray
"""

import sys
import time
from utils import ensure_log_file, timestamp, write_log_entry, LOG_FILE, verify_log_contents, verify_wazuh_alerts

def simulate_t1110():
    print("\n[T1110] Simulating Brute Force Login Attack...")
    ts = timestamp()

    log_entries = []
    for i in range(1, 11):
        entry = (
            f"{ts} wazuh-manager syslog: "
            f"MITRE-ATTACK-SIM: T1110 "
            f"attempt={i} user=admin action=AUTH_FAILED "
            f"src_ip=10.10.10.99 dst_port=22 protocol=SSH"
        )
        log_entries.append(entry)

    success_entry = (
        f"{ts} wazuh-manager syslog: "
        f"MITRE-ATTACK-SIM: T1110 "
        f"attempt=11 user=admin action=AUTH_SUCCESS "
        f"src_ip=10.10.10.99 dst_port=22 protocol=SSH severity=CRITICAL"
    )
    log_entries.append(success_entry)

    success_count = 0
    for entry in log_entries:
        ok, err = write_log_entry(entry)
        if ok:
            success_count += 1

    if success_count == len(log_entries):
        print(f"  \u2713 {success_count} brute force log entries written to {LOG_FILE}")
        print(f"  \u2192 10 failed attempts + 1 successful login simulated")
        print(f"  \u2192 Expected Wazuh rules: 5710/5712 (SSH brute force)")
        print(f"  \u2192 Expected MITRE tag: T1110 - Brute Force")
        return True
    else:
        print(f"  \u2717 Only {success_count}/{len(log_entries)} entries written")
        return False

if __name__ == "__main__":
    ensure_log_file()
    if simulate_t1110():
        verify_log_contents()
        if "--verify" in sys.argv:
            print("\n  Waiting 5s for Wazuh to process logs...")
            time.sleep(5)
            verify_wazuh_alerts(["5710", "5712"])
