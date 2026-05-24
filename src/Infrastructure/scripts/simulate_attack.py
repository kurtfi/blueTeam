#!/usr/bin/env python3
"""
MITRE ATT&CK Attack Simulator
==============================
Simulates MITRE ATT&CK techniques by writing log entries to /var/log/attack_simulation.log
on the wazuh-manager container. Wazuh monitors this file and fires custom rules 100002/100003.

Usage:
    uv run python scripts/simulate_attack.py --t1003
    uv run python scripts/simulate_attack.py --t1059
    uv run python scripts/simulate_attack.py --both
    uv run python scripts/simulate_attack.py --verify
"""

import argparse
import subprocess
import sys
import time
import json
import os
import httpx
from datetime import datetime, timezone

CONTAINER = "wazuh-manager"
LOG_FILE = "/var/log/attack_simulation.log"
WAZUH_API_URL = os.getenv("WAZUH_API_URL", "https://localhost:55000")
WAZUH_API_USER = os.getenv("WAZUH_API_USER", "wazuh-wui")
WAZUH_API_PASS = os.getenv("WAZUH_API_PASSWORD", "wazuh-wui")


def timestamp():
    """Returns ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")


def write_log_entry(log_entry: str) -> tuple[bool, str]:
    """Writes a log entry to the simulation log file using python inside the container."""
    python_cmd = (
        f"import sys; open('{LOG_FILE}', 'a').write(sys.argv[1] + '\\n')"
    )
    full_cmd = [
        "docker", "exec", CONTAINER,
        "python3", "-c", python_cmd, log_entry
    ]
    result = subprocess.run(full_cmd, capture_output=True, text=True)
    return result.returncode == 0, result.stderr


def run_docker_exec(cmd: list[str]) -> tuple[int, str, str]:
    """Executes a generic command inside the wazuh-manager container."""
    full_cmd = ["docker", "exec", CONTAINER] + cmd
    result = subprocess.run(full_cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


def ensure_log_file():
    """Creates the simulation log file on the container if it doesn't exist."""
    rc, out, err = run_docker_exec(["bash", "-c", f"touch {LOG_FILE} && chmod 644 {LOG_FILE}"])
    if rc != 0:
        print(f"  \u2717 Could not create log file: {err}")
        sys.exit(1)
    print(f"  \u2713 Log file ready: {LOG_FILE}")
def simulate_t1003_008():
    """
    T1003.008 - OS Credential Dumping: /etc/shadow Access
    Simulates unauthorized access to /etc/shadow by writing a matching log entry.
    """
    print("\n[T1003.008] Simulating OS Credential Dumping (/etc/shadow access)...")
    ts = timestamp()

    # Simple log entry - no shell special characters
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
        print(f"  ✓ Log entry written to {LOG_FILE}")
        print(f"  → Entry: {log_entry[:120]}")
        print(f"  → Expected Wazuh rule: 100002 (level 10)")
        print(f"  → Expected MITRE tag: T1003.008 - OS Credential Dumping")
    else:
        print(f"  ✗ Failed to write log: {err}")
        return False
    return True


def simulate_t1059_004():
    """
    T1059.004 - Command and Scripting Interpreter: Unix Shell / Reverse Shell
    Simulates a reverse shell by writing a matching log entry.
    """
    print("\n[T1059.004] Simulating Suspicious Command Execution (Reverse Shell)...")
    ts = timestamp()

    # Simple log entry - no shell special characters to avoid bash interpretation
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
        print(f"  ✓ Log entry written to {LOG_FILE}")
        print(f"  → Entry: {log_entry[:120]}")
        print(f"  → Expected Wazuh rule: 100003 (level 10)")
        print(f"  → Expected MITRE tag: T1059.004 - Command Execution")
    else:
        print(f"  ✗ Failed to write log: {err}")
        return False
    return True


def verify_wazuh_alerts():
    """
    Queries Wazuh API to verify that alerts were generated for our simulation rules.
    """
    print("\n[Verify] Querying Wazuh API for simulation alerts...")

    try:
        # Step 1: Authenticate
        auth_resp = httpx.get(
            f"{WAZUH_API_URL}/security/user/authenticate",
            auth=(WAZUH_API_USER, WAZUH_API_PASS),
            verify=False,
            timeout=10.0,
        )
        if auth_resp.status_code != 200:
            print(f"  ✗ Auth failed: {auth_resp.status_code}")
            return

        token = auth_resp.json().get("data", {}).get("token")
        headers = {"Authorization": f"Bearer {token}"}

        # Step 2: Query alerts index in Wazuh Indexer (Elasticsearch)
        es_url = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
        es_user = os.getenv("ELASTICSEARCH_USER", "admin")
        es_pass = os.getenv("ELASTICSEARCH_PASSWORD", "admin")

        query = {
            "query": {
                "terms": {
                    "rule.id": ["100002", "100003"]
                }
            },
            "size": 10,
            "sort": [{"@timestamp": {"order": "desc"}}],
        }

        es_resp = httpx.post(
            f"{es_url}/wazuh-alerts-*/_search",
            json=query,
            auth=(es_user, es_pass),
            verify=False,
            timeout=15.0,
        )

        if es_resp.status_code == 200:
            hits = es_resp.json().get("hits", {}).get("hits", [])
            total = es_resp.json().get("hits", {}).get("total", {}).get("value", 0)
            print(f"  ✓ Found {total} alert(s) for simulation rules (100002/100003)")
            for hit in hits[:5]:
                src = hit.get("_source", {})
                rule = src.get("rule", {})
                print(f"    • [{src.get('@timestamp', '?')}] Rule {rule.get('id')}: {rule.get('description')}")
        else:
            print(f"  → Elasticsearch query returned: {es_resp.status_code}")
            print(f"    (Alerts might still be in the Wazuh Indexer pipeline — wait 30s and retry)")

    except Exception as e:
        print(f"  ✗ Verification error: {e}")
        print(f"    (Make sure all containers are running and accessible)")


def verify_log_contents():
    """Prints the last 10 entries from the simulation log file."""
    print("\n[Verify] Checking simulation log file contents...")
    rc, out, err = run_docker_exec(["bash", "-c", f"tail -n 10 {LOG_FILE} 2>/dev/null || echo 'File empty or not found'"])
    if rc == 0 and out.strip():
        print(f"  ✓ Last entries in {LOG_FILE}:")
        for line in out.strip().split("\n"):
            print(f"    {line}")
    else:
        print(f"  → Log file is empty or missing: {err}")


def check_wazuh_logtest(technique: str):
    """
    Runs wazuh-logtest to verify that a sample log entry would trigger the expected rule.
    """
    print(f"\n[LogTest] Testing rule matching for {technique}...")
    ts = timestamp()

    if technique == "T1003.008":
        test_log = f"{ts} wazuh-manager syslog: MITRE-ATTACK-SIM: T1003.008 user=test file=/etc/shadow"
        expected_rule = "100002"
    else:
        test_log = f"{ts} wazuh-manager syslog: MITRE-ATTACK-SIM: T1059.004 user=test cmd='bash -i'"
        expected_rule = "100003"

    # wazuh-logtest reads from stdin; we echo the log line
    full_cmd = [
        "docker", "exec", "-i", CONTAINER,
        "bash", "-c",
        f"echo '{test_log}' | /var/ossec/bin/wazuh-logtest -q 2>/dev/null | grep -E 'Rule|id:|description:|level:' | head -10"
    ]

    result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=15)
    if result.stdout.strip():
        print(f"  ✓ LogTest output:")
        for line in result.stdout.strip().split("\n"):
            print(f"    {line}")
        if expected_rule in result.stdout:
            print(f"  ✓ Rule {expected_rule} correctly matched!")
        else:
            print(f"  → Rule {expected_rule} not found in output — check ossec.conf restart")
    else:
        print(f"  → No rule match output (wazuh-manager might still be initializing)")


def print_next_steps():
    """Prints manual verification steps for the user."""
    print("\n" + "=" * 60)
    print("NEXT STEPS - Manual Verification")
    print("=" * 60)
    print("""
1. Wazuh Dashboard (http://localhost:5601)
   → Security Events → Search for rule.id:100002 or rule.id:100003
   → Check that alerts appear within 30-60 seconds

2. Shuffle (http://localhost:3001)
   → Auto-import all workflows:
       uv run python scripts/setup_shuffle.py --verify
   → Workflows available:
       shuffle_mitre_workflow.json          (T1003.008 + T1059.004)
       shuffle_brute_force_workflow.json    (T1110)
       shuffle_ransomware_workflow.json     (T1486)

3. TheHive (http://localhost:9000)
   → Cases → Look for "[AGENTIX-SIM]" tagged cases
   → Templates → Verify all 7 MITRE templates exist:
       uv run python scripts/setup_thehive.py

4. Cortex (http://localhost:9001)
   → Jobs → Check VirusTotal_GetReport_3_1 analyzer jobs
   → Organization Settings → Add VirusTotal API key if not set

5. Re-run all simulations:
   uv run python scripts/simulate_attack.py --all --verify
""")


def simulate_t1110():
    """
    T1110 - Brute Force / Password Spray
    Simulates repeated SSH authentication failures from a single source IP.
    """
    print("\n[T1110] Simulating Brute Force Login Attack...")
    ts = timestamp()

    # Simulate 10 rapid auth failures followed by 1 success
    log_entries = []
    for i in range(1, 11):
        entry = (
            f"{ts} wazuh-manager syslog: "
            f"MITRE-ATTACK-SIM: T1110 "
            f"attempt={i} user=admin action=AUTH_FAILED "
            f"src_ip=10.10.10.99 dst_port=22 protocol=SSH"
        )
        log_entries.append(entry)

    # Simulated successful login
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
        print(f"  ✓ {success_count} brute force log entries written to {LOG_FILE}")
        print(f"  → 10 failed attempts + 1 successful login simulated")
        print(f"  → Expected Wazuh rules: 5710/5712 (SSH brute force)")
        print(f"  → Expected MITRE tag: T1110 - Brute Force")
        print(f"  → Expected Playbook: PB-003")
    else:
        print(f"  ✗ Only {success_count}/{len(log_entries)} entries written")
        return False
    return True


def simulate_t1548_001():
    """
    T1548.001 - Privilege Escalation via SUID/SGID Abuse
    Simulates modification of a SUID binary to allow privilege escalation.
    """
    print("\n[T1548.001] Simulating SUID Privilege Escalation...")
    ts = timestamp()

    log_entry = (
        f"{ts} wazuh-manager syslog: "
        f"MITRE-ATTACK-SIM: T1548.001 "
        f"user=www-data pid=9999 "
        f"action=SUID_MODIFIED "
        f"file=/usr/bin/custom_tool "
        f"perm_before=0755 perm_after=4755 "
        f"md5=d41d8cd98f00b204e9800998ecf8427e "
        f"severity=HIGH"
    )

    ok, err = write_log_entry(log_entry)
    if ok:
        print(f"  ✓ SUID modification log entry written to {LOG_FILE}")
        print(f"  → Entry: {log_entry[:120]}")
        print(f"  → Expected Wazuh rule: syscheck (file permission change)")
        print(f"  → Expected MITRE tag: T1548.001 - SUID Abuse")
        print(f"  → Expected Playbook: PB-007")
    else:
        print(f"  ✗ Failed to write log: {err}")
        return False

    # Also simulate root command execution after SUID abuse
    root_entry = (
        f"{ts} wazuh-manager syslog: "
        f"MITRE-ATTACK-SIM: T1548.001 "
        f"user=root pid=10000 "
        f"action=ROOT_SHELL_OBTAINED "
        f"cmd=/usr/bin/custom_tool "
        f"parent_user=www-data "
        f"severity=CRITICAL"
    )
    ok2, _ = write_log_entry(root_entry)
    if ok2:
        print(f"  ✓ Root shell execution log entry written")
    return True


def simulate_t1048():
    """
    T1048 - Data Exfiltration via DNS Tunneling
    Simulates high-volume DNS queries to an unusual domain (DNS tunnel pattern).
    """
    print("\n[T1048] Simulating DNS Exfiltration Tunnel...")
    ts = timestamp()

    # Simulate 5 long DNS queries (encoded data in subdomains)
    dns_domain = "exfil-c2.attacker-controlled.xyz"
    log_entries = []
    for i in range(1, 6):
        encoded_data = "a" * (50 + i * 10)  # Long subdomain simulating base64 encoded data
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
        print(f"  ✓ {success_count} DNS tunnel log entries written to {LOG_FILE}")
        print(f"  → Destination domain: {dns_domain}")
        print(f"  → Expected Wazuh rule: network traffic anomaly")
        print(f"  → Expected MITRE tag: T1048 - Exfiltration via DNS")
        print(f"  → Expected Playbook: PB-005")
    else:
        print(f"  ✗ Only {success_count}/{len(log_entries)} entries written")
        return False
    return True




def main():
    parser = argparse.ArgumentParser(
        description="MITRE ATT&CK Attack Simulator for Agentix/Wazuh environment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --t1003           Simulate credential dumping (T1003.008)
  %(prog)s --t1059           Simulate reverse shell (T1059.004)
  %(prog)s --t1110           Simulate brute force login (T1110)
  %(prog)s --t1548           Simulate SUID privilege escalation (T1548.001)
  %(prog)s --t1048           Simulate DNS exfiltration tunnel (T1048)
  %(prog)s --all             Run ALL 5 simulations
  %(prog)s --all --verify    Run all + verify alerts in Wazuh
  %(prog)s --logtest         Test rule matching via wazuh-logtest
        """,
    )

    parser.add_argument("--t1003", action="store_true", help="Simulate T1003.008 (Credential Dumping)")
    parser.add_argument("--t1059", action="store_true", help="Simulate T1059.004 (Reverse Shell)")
    parser.add_argument("--t1110", action="store_true", help="Simulate T1110 (Brute Force Login)")
    parser.add_argument("--t1548", action="store_true", help="Simulate T1548.001 (SUID Privilege Escalation)")
    parser.add_argument("--t1048", action="store_true", help="Simulate T1048 (DNS Exfiltration Tunnel)")
    parser.add_argument("--both", action="store_true", help="Simulate T1003.008 and T1059.004 (legacy, use --all)")
    parser.add_argument("--all", action="store_true", help="Simulate all 5 MITRE techniques")
    parser.add_argument("--verify", action="store_true", help="Verify alerts after simulation")
    parser.add_argument("--logtest", action="store_true", help="Run wazuh-logtest rule validation")
    parser.add_argument("--wait", type=int, default=5, help="Seconds to wait between simulation and verify (default: 5)")

    args = parser.parse_args()

    if not any([args.t1003, args.t1059, args.t1110, args.t1548, args.t1048, args.both, args.all, args.logtest]):
        parser.print_help()
        sys.exit(0)

    print("=" * 60)
    print("Agentix MITRE ATT&CK Simulator")
    print("=" * 60)
    print(f"  Container : {CONTAINER}")
    print(f"  Log file  : {LOG_FILE}")
    print(f"  Timestamp : {datetime.now().isoformat()}")

    # Ensure log file exists
    ensure_log_file()

    ran_simulation = False

    if args.logtest:
        check_wazuh_logtest("T1003.008")
        check_wazuh_logtest("T1059.004")

    if args.t1003 or args.both or args.all:
        simulate_t1003_008()
        ran_simulation = True

    if args.t1059 or args.both or args.all:
        simulate_t1059_004()
        ran_simulation = True

    if args.t1110 or args.all:
        simulate_t1110()
        ran_simulation = True

    if args.t1548 or args.all:
        simulate_t1548_001()
        ran_simulation = True

    if args.t1048 or args.all:
        simulate_t1048()
        ran_simulation = True

    if ran_simulation:
        verify_log_contents()

        if args.verify:
            print(f"\n  Waiting {args.wait}s for Wazuh to process logs...")
            time.sleep(args.wait)
            verify_wazuh_alerts()

    print_next_steps()


if __name__ == "__main__":
    main()
