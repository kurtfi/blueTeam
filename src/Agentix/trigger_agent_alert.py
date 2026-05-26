import os
import httpx
import hmac
import hashlib
import json
import sys

API_URL = "http://localhost:8001/v1/webhooks/wazuh"
WEBHOOK_SECRET = os.getenv("AGENTIX_WEBHOOK_SECRET")

if not WEBHOOK_SECRET:
    print("Error: AGENTIX_WEBHOOK_SECRET environment variable is required.")
    sys.exit(1)

def main():
    print("=== Triggering AI Agent Triage Workflow ===")
    
    # 1. Prepare simulated alert payload for T1003.008 (Credential Dumping)
    alert_payload = {
        "rule": {
            "id": "100002",
            "description": "MITRE T1003.008 - OS Credential Dumping (/etc/shadow access)",
            "level": 10,
            "groups": ["mitre_t1003", "credential_dumping"],
            "mitre": {
                "id": ["T1003", "T1003.008"],
                "tactic": ["Credential Access"],
                "technique": ["OS Credential Dumping"]
            }
        },
        "agent": {
            "id": "000",
            "name": "wazuh-manager",
            "ip": "127.0.0.1"
        },
        "data": {
            "srcip": "10.10.10.99",
            "srcuser": "www-data",
            "command": "cat /etc/shadow"
        },
        "full_log": "May 23 07:27:26 wazuh-manager syslog: MITRE-ATTACK-SIM: T1003.008 user=www-data pid=31337 cmd=cat-etc-shadow file=/etc/shadow action=READ severity=CRITICAL src_ip=10.10.10.99",
        "timestamp": "2026-05-23T07:27:26.542Z",
        "location": "/var/log/attack_simulation.log"
    }

    # Calculate HMAC signature
    payload_bytes = json.dumps(alert_payload).encode("utf-8")
    signature = hmac.new(WEBHOOK_SECRET.encode(), payload_bytes, hashlib.sha256).hexdigest()

    headers = {
        "X-Webhook-Signature": signature,
        "Content-Type": "application/json"
    }

    # 2. POST to webhooks endpoint
    print(f"Sending alert to {API_URL}...")
    resp = httpx.post(API_URL, content=payload_bytes, headers=headers, timeout=10.0)
    print(f"Status Code: {resp.status_code}")
    print(f"Response: {resp.text}")

if __name__ == "__main__":
    main()
