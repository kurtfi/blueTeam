import os
import httpx

API_URL = "http://localhost:8001/v1/webhooks/shuffle/wazuh"
API_KEY = "dev-internal-key-change-me-in-production"

def main():
    print("=== Triggering Brute Force AI Agent Triage Workflow (T1110) ===")
    
    # Prepare simulated alert payload for T1110 (Brute Force)
    alert_payload = {
        "rule": {
            "id": "5712",
            "description": "sshd: SSH Brute Force login attempt success after failures",
            "level": 10,
            "groups": ["syslog", "sshd", "authentication_failures"],
            "mitre": {
                "id": ["T1110", "T1110.001"],
                "tactic": ["Credential Access"],
                "technique": ["Brute Force"]
            }
        },
        "agent": {
            "id": "001",
            "name": "linux-prod-web",
            "ip": "10.10.10.2"
        },
        "data": {
            "srcip": "10.10.10.99",
            "dstuser": "admin",
            "target_user": "admin",
            "srcport": "44321"
        },
        "full_log": "May 23 11:54:20 wazuh-manager syslog: MITRE-ATTACK-SIM: T1110 attempt=11 user=admin action=AUTH_SUCCESS src_ip=10.10.10.99 dst_port=22 protocol=SSH severity=CRITICAL",
        "timestamp": "2026-05-23T11:54:20.000Z",
        "location": "/var/log/attack_simulation.log"
    }

    headers = {
        "X-Internal-Api-Key": API_KEY,
        "Content-Type": "application/json"
    }

    print(f"Sending alert to {API_URL}...")
    resp = httpx.post(API_URL, json=alert_payload, headers=headers, timeout=10.0)
    print(f"Status Code: {resp.status_code}")
    print(f"Response: {resp.text}")

if __name__ == "__main__":
    main()
