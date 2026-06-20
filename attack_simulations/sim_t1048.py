#!/usr/bin/env python3
"""
Simulate T1048 - Data Exfiltration via DNS Tunneling
"""

from utils import LOG_FILE, SimulationRunner, timestamp, write_log_entry


def simulate_t1048():
    ts = timestamp()

    dns_domain = "exfil-c2.attacker-controlled.xyz"
    log_entries = []
    for i in range(1, 6):
        encoded_data = "a" * (50 + i * 10)
        entry = (
            f"{ts} wazuh-manager syslog: "
            f"MITRE-ATTACK-SIM: T1048 "
            f"query={i} "
            f"qname={encoded_data}.{dns_domain} "
            f"qtype=TXT "
            f"src_ip=10.0.0.5 "
            f"action=DNS_QUERY_EXFIL "
            f"severity=HIGH"
        )
        log_entries.append(entry)

    success_count = 0
    for entry in log_entries:
        ok, err = write_log_entry(entry)
        if ok:
            success_count += 1

    if success_count == len(log_entries):
        print(f"  \u2713 {success_count} DNS tunnel log entries written to {LOG_FILE}")
        print(f"  \u2192 Destination domain: {dns_domain}")
        print("  \u2192 Expected Wazuh rule: network traffic anomaly")
        print("  \u2192 Expected MITRE tag: T1048 - Exfiltration via DNS")
        return True
    else:
        print(f"  \u2717 Only {success_count}/{len(log_entries)} entries written")
        return False


if __name__ == "__main__":
    runner = SimulationRunner(
        name="T1048",
        description="Data Exfiltration via DNS Tunneling",
        expected_rules=["100005"]
    )
    runner.run(simulate_t1048)

