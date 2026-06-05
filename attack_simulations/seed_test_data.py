#!/usr/bin/env python3
"""
seed_test_data.py — Inject realistic Wazuh alert documents into Elasticsearch.

These documents are structured exactly the same way Wazuh writes alerts, so the
TriageCore WazuhProvider.query_logs() and get_endpoint_info() will find and return
them without any modifications to production code.

Usage:
    uv run python attack_simulations/seed_test_data.py
    uv run python attack_simulations/seed_test_data.py --clean   # remove seeded docs only
"""

import argparse
import sys
from datetime import UTC, datetime

import httpx

ES_URL = "http://localhost:9200"
ES_USER = "admin"
ES_PASS = "admin"
INDEX = "wazuh-alerts-4.x-agentix-demo"

# Tag on every seeded document so --clean can remove them precisely
SEED_TAG = "agentix-demo-seed"
SEED_FIELD = "x_seed_tag"  # custom field prefix avoids ES reserved _ namespace


def _headers() -> dict:
    return {"Content-Type": "application/json"}


def _auth() -> tuple:
    return (ES_USER, ES_PASS)


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


# ─────────────────────────────────────────────────────────────────────────────
# Alert documents
# ─────────────────────────────────────────────────────────────────────────────

ALERTS = [
    # ── SSH Brute Force + Privilege Escalation (rule 100002) ─────────────────
    {
        "_id": "agentix-demo-ssh-brute-1",
        "source": {
            "@timestamp": _now(),
            "x_seed_tag": SEED_TAG,
            "agent": {"id": "1", "name": "server-prod-01"},
            "rule": {
                "id": "100002",
                "level": 12,
                "description": "SSH Brute Force login followed by successful privilege escalation",
                "groups": ["authentication_failures", "mitre_t1110", "mitre_t1548"],
                "mitre": {"id": ["T1110", "T1548.001"], "tactic": ["Credential Access", "Privilege Escalation"]},
            },
            "data": {
                "srcip": "198.51.100.45",
                "dstuser": "root",
                "dstport": "22",
                "protocol": "ssh",
                "action": "AUTH_SUCCESS_AFTER_BRUTEFORCE",
            },
            "full_log": (
                "Jun 05 10:00:01 server-prod-01 sshd[1234]: "
                "Accepted password for root from 198.51.100.45 port 51234 ssh2 "
                "(after 47 failed attempts)"
            ),
            "location": "/var/log/auth.log",
        },
    },
    # ── C2 Beaconing / Reverse Shell (rule 100003) ────────────────────────────
    {
        "_id": "agentix-demo-c2-beacon-1",
        "source": {
            "@timestamp": _now(),
            "x_seed_tag": SEED_TAG,
            "agent": {"id": "2", "name": "host-win10-08"},
            "rule": {
                "id": "100003",
                "level": 14,
                "description": "Suspicious outbound traffic pattern — potential C2 beaconing",
                "groups": ["network_anomaly", "mitre_t1059", "mitre_t1071"],
                "mitre": {"id": ["T1059.001", "T1071.001"], "tactic": ["Execution", "Command and Control"]},
            },
            "data": {
                "srcip": "192.168.1.45",
                "dstip": "203.0.113.88",
                "dstport": "443",
                "protocol": "tcp",
                "process_name": "powershell.exe",
                "action": "OUTBOUND_HTTPS_SUSPICIOUS",
            },
            "full_log": (
                "Jun 05 10:05:33 host-win10-08 sysmon[8888]: "
                "Network connection detected: powershell.exe → 203.0.113.88:443 "
                "beacon_interval=60s total_bytes=1.2MB"
            ),
            "location": "EventLog",
        },
    },
    # ── Credential Dumping (rule 100002 alt) ─────────────────────────────────
    {
        "_id": "agentix-demo-cred-dump-1",
        "source": {
            "@timestamp": _now(),
            "x_seed_tag": SEED_TAG,
            "agent": {"id": "1", "name": "server-prod-01"},
            "rule": {
                "id": "100002",
                "level": 10,
                "description": "MITRE ATT&CK T1003.008 — OS Credential Dumping (/etc/shadow access)",
                "groups": ["local", "syslog", "mitre_t1003"],
                "mitre": {"id": ["T1003.008"], "tactic": ["Credential Access"]},
            },
            "data": {
                "srcip": "198.51.100.45",
                "dstuser": "www-data",
                "action": "READ",
                "file": "/etc/shadow",
            },
            "full_log": (
                "Jun 05 10:01:15 server-prod-01 syslog: "
                "MITRE-ATTACK-SIM: T1003.008 user=www-data pid=31337 "
                "cmd=cat-etc-shadow file=/etc/shadow action=READ severity=CRITICAL src_ip=198.51.100.45"
            ),
            "location": "/var/log/attack_simulation.log",
        },
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def create_index(client: httpx.Client) -> None:
    """Create the demo index if it does not exist."""
    r = client.put(
        f"{ES_URL}/{INDEX}",
        headers=_headers(),
        auth=_auth(),
        json={
            "settings": {"number_of_shards": 1, "number_of_replicas": 0},
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "x_seed_tag": {"type": "keyword"},
                    "full_log": {"type": "text"},
                    "agent": {
                        "properties": {
                            "id": {"type": "keyword"},
                            "name": {"type": "keyword"},
                        }
                    },
                    "rule": {
                        "properties": {
                            "id": {"type": "keyword"},
                            "level": {"type": "integer"},
                            "description": {"type": "text"},
                            "groups": {"type": "keyword"},
                        }
                    },
                    "data": {
                        "properties": {
                            "srcip": {"type": "ip"},
                            "dstip": {"type": "ip"},
                            "dstuser": {"type": "keyword"},
                            "dstport": {"type": "keyword"},
                            "protocol": {"type": "keyword"},
                            "process_name": {"type": "keyword"},
                            "action": {"type": "keyword"},
                            "file": {"type": "keyword"},
                        }
                    },
                }
            },
        },
        timeout=15.0,
    )
    if r.status_code in (200, 400):  # 400 = already exists
        existing = r.status_code == 400
        print(f"  {'✓ Index already exists' if existing else '✓ Index created'}: {INDEX}")
    else:
        print(f"  ✗ Failed to create index: {r.status_code} {r.text}")
        sys.exit(1)


def seed(client: httpx.Client) -> None:
    """Upsert each alert document."""
    print(f"\n[Seed] Inserting {len(ALERTS)} demo alert(s) into {INDEX}…")
    ok = 0
    for alert in ALERTS:
        doc_id = alert["_id"]
        r = client.put(
            f"{ES_URL}/{INDEX}/_doc/{doc_id}",
            headers=_headers(),
            auth=_auth(),
            json=alert["source"],
            timeout=15.0,
        )
        if r.status_code in (200, 201):
            result = r.json().get("result", "?")
            print(f"  ✓ [{result}] {doc_id}")
            ok += 1
        else:
            print(f"  ✗ {doc_id}: {r.status_code} {r.text[:120]}")
    print(f"\n  {ok}/{len(ALERTS)} document(s) seeded successfully.")


def clean(client: httpx.Client) -> None:
    """Delete all documents tagged with SEED_TAG from the demo index."""
    print(f"\n[Clean] Removing seeded documents from {INDEX}…")
    r = client.post(
        f"{ES_URL}/{INDEX}/_delete_by_query",
        headers=_headers(),
        auth=_auth(),
        json={"query": {"term": {"x_seed_tag": SEED_TAG}}},
        timeout=30.0,
    )
    if r.status_code == 200:
        deleted = r.json().get("deleted", 0)
        print(f"  ✓ {deleted} document(s) removed.")
    else:
        print(f"  ✗ Delete failed: {r.status_code} {r.text[:200]}")


def verify(client: httpx.Client) -> None:
    """Quick read-back verification."""
    print(f"\n[Verify] Reading back seeded alerts from {INDEX}…")
    r = client.post(
        f"{ES_URL}/{INDEX}/_search",
        headers=_headers(),
        auth=_auth(),
        json={
            "query": {"term": {"x_seed_tag": SEED_TAG}},
            "size": 10,
            "_source": ["@timestamp", "rule.id", "rule.description", "agent.name", "data.srcip"],
        },
        timeout=15.0,
    )
    if r.status_code != 200:
        print(f"  ✗ Search failed: {r.status_code}")
        return
    hits = r.json().get("hits", {}).get("hits", [])
    print(f"  ✓ Found {len(hits)} seeded document(s):")
    for hit in hits:
        src = hit["_source"]
        rule_id = src.get("rule", {}).get("id", "?")
        desc = src.get("rule", {}).get("description", "?")[:60]
        agent = src.get("agent", {}).get("name", "?")
        srcip = src.get("data", {}).get("srcip", "N/A")
        print(f"    • rule:{rule_id} agent:{agent} src:{srcip} — {desc}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed demo Wazuh alerts into Elasticsearch")
    parser.add_argument("--clean", action="store_true", help="Remove seeded documents instead of inserting")
    args = parser.parse_args()

    with httpx.Client() as client:
        # Connectivity check
        try:
            r = client.get(f"{ES_URL}/_cluster/health", auth=_auth(), timeout=5.0)
            r.raise_for_status()
            status = r.json().get("status", "?")
            print(f"✓ Elasticsearch reachable — cluster status: {status}")
        except Exception as e:
            print(f"✗ Cannot reach Elasticsearch at {ES_URL}: {e}")
            sys.exit(1)

        if args.clean:
            clean(client)
        else:
            create_index(client)
            seed(client)
            verify(client)
            print(
                "\n✓ Done. TriageCore will now find these alerts when querying "
                "the wazuh-alerts-* indices.\n"
                "  Run with --clean to remove them when done.\n"
            )


if __name__ == "__main__":
    main()
