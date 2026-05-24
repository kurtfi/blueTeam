#!/usr/bin/env python3
"""
Shuffle Workflow Auto-Import Script
=====================================
Automatically imports all Agentix SOC playbook workflows into Shuffle SOAR.

Prerequisites:
  - Shuffle must be running at SHUFFLE_URL (default: http://localhost:3001)
  - You need a Shuffle API key (create at: Shuffle UI → Settings → API Keys)
  - Set SHUFFLE_API_KEY in your .env file before running

Workflows imported:
  1. shuffle_mitre_workflow.json     → Agentix MITRE ATT&CK Response (T1003/T1059)
  2. shuffle_brute_force_workflow.json → Agentix Brute Force Response (T1110)
  3. shuffle_ransomware_workflow.json  → Agentix Ransomware Emergency Response (T1486)

Usage:
    uv run python scripts/setup_shuffle.py
    uv run python scripts/setup_shuffle.py --list   # list existing workflows
    uv run python scripts/setup_shuffle.py --verify  # verify import + print webhook URLs
"""

import os
import sys
import json
import time
import argparse
import httpx
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

SHUFFLE_URL = os.getenv("SHUFFLE_URL", "http://localhost:3001")
SHUFFLE_BACKEND_URL = os.getenv("SHUFFLE_BACKEND_URL", "http://localhost:5001")
SHUFFLE_API_KEY = os.getenv("SHUFFLE_API_KEY", "")

SCRIPTS_DIR = Path(__file__).parent

WORKFLOW_FILES = [
    {
        "file": "shuffle_mitre_workflow.json",
        "name": "Agentix MITRE ATT&CK Response",
        "description": "T1003.008 (Credential Dumping) + T1059.004 (Reverse Shell)",
        "webhook_trigger": "wazuh_alerts",
    },
    {
        "file": "shuffle_brute_force_workflow.json",
        "name": "Agentix Brute Force Response",
        "description": "T1110 (Brute Force / Password Spray)",
        "webhook_trigger": "wazuh_brute_force",
    },
    {
        "file": "shuffle_ransomware_workflow.json",
        "name": "Agentix Ransomware Emergency Response",
        "description": "T1486 (Ransomware / Mass Encryption) – P0",
        "webhook_trigger": "wazuh_ransomware",
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def get_auth_headers() -> dict:
    if not SHUFFLE_API_KEY:
        print("  ✗ SHUFFLE_API_KEY is not set in .env")
        print("    → Create an API key at: Shuffle UI → Settings → API Keys")
        sys.exit(1)
    return {
        "Authorization": f"Bearer {SHUFFLE_API_KEY}",
        "Content-Type": "application/json",
    }


def check_shuffle_connectivity(client: httpx.Client) -> bool:
    """Checks if Shuffle backend is reachable."""
    for url in [SHUFFLE_BACKEND_URL, SHUFFLE_URL]:
        try:
            resp = client.get(f"{url}/api/v1/health", timeout=5.0)
            if resp.status_code in (200, 401):  # 401 = reachable but unauth
                print(f"  ✓ Shuffle is reachable at {url} (status: {resp.status_code})")
                return True
        except Exception:
            continue
    return False


def list_existing_workflows(client: httpx.Client, headers: dict) -> list[dict]:
    """Lists all existing workflows in Shuffle."""
    resp = client.get(f"{SHUFFLE_BACKEND_URL}/api/v1/workflows", headers=headers, timeout=15.0)
    if resp.status_code == 200:
        return resp.json() if isinstance(resp.json(), list) else []
    return []


def import_workflow(client: httpx.Client, headers: dict, workflow_path: Path) -> dict | None:
    """
    Imports a workflow JSON file into Shuffle.
    Returns the created workflow data or None on failure.
    """
    print(f"\n  Importing: {workflow_path.name}")

    if not workflow_path.exists():
        print(f"  ✗ File not found: {workflow_path}")
        return None

    with open(workflow_path, "r") as f:
        workflow_data = json.load(f)

    workflow_name = workflow_data.get("name", workflow_path.stem)

    # Check if already imported (by name)
    existing = list_existing_workflows(client, headers)
    for wf in existing:
        if wf.get("name") == workflow_name:
            print(f"  → Already exists (id={wf.get('id', '?')}) – skipping import.")
            return wf

    # Import via PUT /api/v1/workflows
    resp = client.post(
        f"{SHUFFLE_BACKEND_URL}/api/v1/workflows",
        json=workflow_data,
        headers=headers,
        timeout=30.0,
    )

    if resp.status_code in (200, 201):
        result = resp.json()
        wf_id = result.get("id", "?")
        print(f"  ✓ Imported successfully. Workflow ID: {wf_id}")
        return result
    else:
        # Try alternative endpoint (older Shuffle versions)
        resp2 = client.put(
            f"{SHUFFLE_BACKEND_URL}/api/v1/workflows",
            json=workflow_data,
            headers=headers,
            timeout=30.0,
        )
        if resp2.status_code in (200, 201):
            result = resp2.json()
            wf_id = result.get("id", "?")
            print(f"  ✓ Imported successfully (PUT). Workflow ID: {wf_id}")
            return result
        else:
            print(f"  ✗ Import failed: {resp.status_code} – {resp.text[:200]}")
            return None


def get_webhook_url(client: httpx.Client, headers: dict, workflow_id: str, trigger_name: str) -> str:
    """Retrieves the webhook URL for a workflow's trigger."""
    try:
        resp = client.get(
            f"{SHUFFLE_BACKEND_URL}/api/v1/workflows/{workflow_id}",
            headers=headers,
            timeout=10.0,
        )
        if resp.status_code == 200:
            wf_data = resp.json()
            triggers = wf_data.get("triggers", [])
            for trigger in triggers:
                if trigger.get("name") == trigger_name or trigger.get("id", "").endswith(trigger_name):
                    hook_id = trigger.get("id", "")
                    if hook_id:
                        return f"{SHUFFLE_BACKEND_URL}/api/v1/hooks/webhook_{hook_id}"
    except Exception:
        pass
    return f"{SHUFFLE_BACKEND_URL}/api/v1/hooks/webhook_{trigger_name} (ID may differ after import)"


def print_wazuh_integration_snippet(webhook_urls: dict[str, str]) -> None:
    """Prints the ossec.conf integration block for configuring Wazuh webhooks."""
    print("\n" + "=" * 70)
    print("Wazuh ossec.conf Integration Snippet")
    print("=" * 70)
    print("Add the following blocks to /var/ossec/etc/ossec.conf on wazuh-manager:")
    print()

    mitre_url = webhook_urls.get("shuffle_mitre_workflow", "http://shuffle-backend:5001/api/v1/hooks/webhook_wazuh_alerts")
    brute_url = webhook_urls.get("shuffle_brute_force_workflow", "http://shuffle-backend:5001/api/v1/hooks/webhook_wazuh_brute_force")
    ransom_url = webhook_urls.get("shuffle_ransomware_workflow", "http://shuffle-backend:5001/api/v1/hooks/webhook_wazuh_ransomware")

    print(f"""  <!-- MITRE ATT&CK Response (T1003.008 + T1059.004) -->
  <integration>
    <name>shuffle</name>
    <hook_url>{mitre_url}</hook_url>
    <rule_id>100002,100003</rule_id>
    <alert_format>json</alert_format>
  </integration>

  <!-- Brute Force Response (T1110) -->
  <integration>
    <name>shuffle</name>
    <hook_url>{brute_url}</hook_url>
    <group>authentication_failures</group>
    <alert_format>json</alert_format>
  </integration>

  <!-- Ransomware Emergency Response (T1486) -->
  <integration>
    <name>shuffle</name>
    <hook_url>{ransom_url}</hook_url>
    <group>syscheck</group>
    <level>12</level>
    <alert_format>json</alert_format>
  </integration>""")

    print("\nAfter editing ossec.conf, restart Wazuh manager:")
    print("  docker exec wazuh-manager /var/ossec/bin/wazuh-control restart")


def update_env_file(key: str, value: str) -> None:
    """Updates or appends a key=value pair in the .env file."""
    env_path = SCRIPTS_DIR.parent / ".env"
    if not env_path.exists():
        return

    content = env_path.read_text()
    if f"{key}=" in content:
        lines = [
            f"{key}={value}" if line.startswith(f"{key}=") else line
            for line in content.splitlines()
        ]
        env_path.write_text("\n".join(lines) + "\n")
    else:
        with open(env_path, "a") as f:
            f.write(f"\n{key}={value}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Agentix Shuffle Workflow Auto-Import",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                 Import all workflows
  %(prog)s --list          List existing workflows in Shuffle
  %(prog)s --verify        Import + print webhook URLs
  %(prog)s --no-env        Skip .env SHUFFLE_WEBHOOK_* variable update
        """,
    )
    parser.add_argument("--list", action="store_true", help="List existing workflows and exit")
    parser.add_argument("--verify", action="store_true", help="Print webhook URLs after import")
    parser.add_argument("--no-env", action="store_true", help="Skip .env SHUFFLE_WEBHOOK_* update")
    args = parser.parse_args()

    print("=" * 70)
    print("Agentix Shuffle Workflow Import")
    print("=" * 70)
    print(f"  Shuffle URL    : {SHUFFLE_BACKEND_URL}")
    print(f"  API Key        : {'configured (' + SHUFFLE_API_KEY[:8] + '...)' if SHUFFLE_API_KEY else 'NOT SET – check .env'}")
    print()

    headers = get_auth_headers()

    with httpx.Client(timeout=30.0) as client:
        # Connectivity check
        print("[Connectivity] Checking Shuffle backend...")
        if not check_shuffle_connectivity(client):
            print(f"  → Shuffle health check returned unexpected status, but trying to proceed anyway...")

        # List mode
        if args.list:
            print("\n[Workflows] Existing workflows in Shuffle:")
            workflows = list_existing_workflows(client, headers)
            if workflows:
                for wf in workflows:
                    print(f"  • {wf.get('name', '?')} (id={wf.get('id', '?')})")
            else:
                print("  → No workflows found (or API key has no permissions).")
            return

        # Import all workflows
        imported: dict[str, dict] = {}
        webhook_urls: dict[str, str] = {}

        print("\n[Import] Importing SOC playbook workflows...")
        for wf_def in WORKFLOW_FILES:
            wf_path = SCRIPTS_DIR / wf_def["file"]
            result = import_workflow(client, headers, wf_path)
            if result:
                stem = wf_def["file"].replace(".json", "")
                imported[stem] = result
                wf_id = result.get("id", "")
                if wf_id and (args.verify or not args.no_env):
                    time.sleep(0.5)  # brief pause to let Shuffle register the workflow
                    webhook_url = get_webhook_url(client, headers, wf_id, wf_def["webhook_trigger"])
                    webhook_urls[stem] = webhook_url

        # Print summary
        print(f"\n[Summary] {len(imported)}/{len(WORKFLOW_FILES)} workflows imported successfully.")

        if args.verify and webhook_urls:
            print("\n[Webhook URLs]")
            for stem, url in webhook_urls.items():
                print(f"  {stem}:")
                print(f"    {url}")

            # Update .env with webhook URLs
            if not args.no_env:
                print("\n[.env] Updating SHUFFLE_WEBHOOK_* variables...")
                for stem, url in webhook_urls.items():
                    key = f"SHUFFLE_WEBHOOK_{stem.upper()}"
                    update_env_file(key, url)
                    print(f"  ✓ {key}={url[:60]}...")

        # Print Wazuh ossec.conf snippet
        print_wazuh_integration_snippet(webhook_urls)

        print("\n" + "=" * 70)
        print("Shuffle Import Complete")
        print("=" * 70)
        print("""
Next Steps:
  1. Open Shuffle UI: http://localhost:3001
  2. Go to each workflow and verify the graph structure looks correct
  3. Set workflow variables (CORTEX_API_KEY, THEHIVE_API_KEY) in each workflow
  4. Copy the webhook URLs above into Wazuh ossec.conf
  5. Restart Wazuh manager:
       docker exec wazuh-manager /var/ossec/bin/wazuh-control restart
  6. Test with:
       uv run python scripts/simulate_attack.py --t1003 --verify
       uv run python scripts/simulate_attack.py --t1059 --verify
       uv run python scripts/simulate_attack.py --t1110 --verify
""")


if __name__ == "__main__":
    main()
