#!/usr/import/env python3
"""
Simulate T1110 - Brute Force / Password Spray
"""

import sys
import time

from utils import LOG_FILE, ensure_log_file, timestamp, verify_log_contents, verify_wazuh_alerts, write_log_entry


def simulate_t1110():
    print("\n[T1110] Simulating Brute Force Login Attack...")

    success_count = 0
    # Write 10 failed attempts with dynamic timestamps
    for i in range(1, 11):
        ts = timestamp()
        entry = (
            f"{ts} wazuh-manager syslog: "
            f"MITRE-ATTACK-SIM: T1110 "
            f"attempt={i} user=admin action=AUTH_FAILED "
            f"src_ip=10.10.10.99 dst_port=22 protocol=SSH"
        )
        ok, err = write_log_entry(entry)
        if ok:
            success_count += 1
        time.sleep(0.1)

    # Sleep 1.5 seconds to ensure different second for success
    print("  Waiting 1.5s before successful login...")
    time.sleep(1.5)

    ts_success = timestamp()
    success_entry = (
        f"{ts_success} wazuh-manager syslog: "
        f"MITRE-ATTACK-SIM: T1110 "
        f"attempt=11 user=admin action=AUTH_SUCCESS "
        f"src_ip=10.10.10.99 dst_port=22 protocol=SSH severity=CRITICAL"
    )
    ok, err = write_log_entry(success_entry)
    if ok:
        success_count += 1

    if success_count == 11:
        print(f"  \u2713 {success_count} brute force log entries written to {LOG_FILE}")
        print("  \u2192 10 failed attempts + 1 successful login simulated")
        print("  \u2192 Expected Wazuh rules: 100011 (Brute Force correlated)")
        print("  \u2192 Expected MITRE tag: T1110 - Brute Force")
        return True
    else:
        print(f"  \u2717 Only {success_count}/11 entries written")
        return False


if __name__ == "__main__":
    ensure_log_file()
    if simulate_t1110():
        verify_log_contents()
        if "--verify" in sys.argv:
            print("\n  Waiting 5s for Wazuh to process logs...")
            time.sleep(5)
            verify_wazuh_alerts(["100011"])
