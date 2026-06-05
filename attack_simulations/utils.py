import os
import subprocess
import sys
from datetime import UTC, datetime

import httpx

CONTAINER = "wazuh-manager"
LOG_FILE = "/var/log/attack_simulation.log"
WAZUH_API_URL = os.getenv("WAZUH_API_URL", "https://localhost:55000")
WAZUH_API_USER = os.getenv("WAZUH_API_USER", "wazuh-wui")
WAZUH_API_PASS = os.getenv("WAZUH_API_PASSWORD", "wazuh-wui")

def timestamp():
    """Returns ISO-8601 UTC timestamp."""
    return datetime.now(UTC).strftime("%b %d %H:%M:%S")

def run_docker_exec(cmd: list[str]) -> tuple[int, str, str]:
    """Executes a generic command inside the wazuh-manager container."""
    full_cmd = ["docker", "exec", CONTAINER] + cmd
    result = subprocess.run(full_cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr

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

def ensure_log_file():
    """Creates the simulation log file on the container if it doesn't exist."""
    rc, out, err = run_docker_exec(["bash", "-c", f"touch {LOG_FILE} && chmod 644 {LOG_FILE}"])
    if rc != 0:
        print(f"  \u2717 Could not create log file: {err}")
        sys.exit(1)
    print(f"  \u2713 Log file ready: {LOG_FILE}")

def verify_log_contents():
    """Prints the last 10 entries from the simulation log file."""
    print("\n[Verify] Checking simulation log file contents...")
    rc, out, err = run_docker_exec(["bash", "-c", f"tail -n 10 {LOG_FILE} 2>/dev/null || echo 'File empty or not found'"])
    if rc == 0 and out.strip():
        print(f"  \u2713 Last entries in {LOG_FILE}:")
        for line in out.strip().split("\n"):
            print(f"    {line}")
    else:
        print(f"  \u2192 Log file is empty or missing: {err}")

def verify_wazuh_alerts(expected_rules: list[str] = None):
    """
    Queries Wazuh API to verify that alerts were generated for our simulation rules.
    """
    print("\n[Verify] Querying Wazuh API for simulation alerts...")
    try:
        auth_resp = httpx.get(
            f"{WAZUH_API_URL}/security/user/authenticate",
            auth=(WAZUH_API_USER, WAZUH_API_PASS),
            verify=False,
            timeout=10.0,
        )
        if auth_resp.status_code != 200:
            print(f"  \u2717 Auth failed: {auth_resp.status_code}")
            return


        es_url = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
        es_user = os.getenv("ELASTICSEARCH_USER", "admin")
        es_pass = os.getenv("ELASTICSEARCH_PASSWORD", "admin")

        query_terms = expected_rules if expected_rules else ["100002", "100003", "5710", "5712"]
        query = {
            "query": {
                "terms": {
                    "rule.id": query_terms
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
            print(f"  \u2713 Found {total} alert(s) matching expected rules: {query_terms}")
            for hit in hits[:5]:
                src = hit.get("_source", {})
                rule = src.get("rule", {})
                print(f"    \u2022 [{src.get('@timestamp', '?')}] Rule {rule.get('id')}: {rule.get('description')}")
        else:
            print(f"  \u2192 Elasticsearch query returned: {es_resp.status_code}")
            print("    (Alerts might still be in the Wazuh Indexer pipeline \u2014 wait 30s and retry)")

    except Exception as e:
        print(f"  \u2717 Verification error: {e}")
        print("    (Make sure all containers are running and accessible)")
