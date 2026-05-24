#!/usr/bin/env python3
"""
Cortex Setup Script
====================
Creates an organization and API key in Cortex for the Agentix MITRE ATT&CK lab,
and enables the VirusTotal_GetReport_3_1 analyzer.

Prerequisites:
  - Cortex must be running at CORTEX_URL (default: http://localhost:9001)
  - First-time setup: Cortex needs to be initialised via its web UI first
    (http://localhost:9001 → Update database → Create admin user)

Usage:
    uv run python scripts/setup_cortex.py
"""

import os
import sys
import json
import httpx
from dotenv import load_dotenv

load_dotenv()

CORTEX_URL = os.getenv("CORTEX_URL", "http://localhost:9001")
CORTEX_ADMIN_USER = "admin"
CORTEX_ADMIN_PASS = os.getenv("CORTEX_ADMIN_PASSWORD", "secret")  # set if you changed it

ORG_NAME = "agentix-lab"
ORG_DESCRIPTION = "Agentix MITRE ATT&CK Lab Organization"
ANALYST_LOGIN = "agentix-analyst"
ANALYST_NAME = "Agentix Analyst"
ANALYST_PASS = "Agentix-Lab-2025!"
ANALYST_ROLES = ["read", "analyze", "orgadmin"]


def get_admin_token(client: httpx.Client) -> str:
    """Authenticates as admin and returns a JWT token."""
    print(f"  → Authenticating as Cortex admin ({CORTEX_ADMIN_USER})...")
    resp = client.post(
        f"{CORTEX_URL}/api/login",
        json={"user": CORTEX_ADMIN_USER, "password": CORTEX_ADMIN_PASS},
    )
    if resp.status_code != 200:
        print(f"  ✗ Admin login failed: {resp.status_code} – {resp.text}")
        print()
        print("  IMPORTANT: Before running this script, complete Cortex first-time setup:")
        print(f"    1. Open http://localhost:9001 in your browser")
        print(f"    2. Click 'Update database'")
        print(f"    3. Create an admin account (user: admin, password of your choice)")
        print(f"    4. Set CORTEX_ADMIN_PASSWORD in .env to that password")
        print(f"    5. Run this script again")
        sys.exit(1)
    token = resp.json().get("token", "")
    print("  ✓ Admin authentication successful.")
    return token


def ensure_organization(client: httpx.Client, headers: dict) -> str:
    """Creates the agentix-lab organization if it doesn't exist. Returns org id."""
    print(f"\n[Organization] Checking '{ORG_NAME}'...")
    resp = client.get(f"{CORTEX_URL}/api/organization", headers=headers)
    if resp.status_code == 200:
        orgs = resp.json() if isinstance(resp.json(), list) else []
        for org in orgs:
            if org.get("name") == ORG_NAME:
                print(f"  → Already exists (id={org.get('id', org.get('_id', '?'))})")
                return org.get("id", org.get("_id", ""))

    # Create org
    create_resp = client.post(
        f"{CORTEX_URL}/api/organization",
        json={"name": ORG_NAME, "description": ORG_DESCRIPTION, "status": "Active"},
        headers=headers,
    )
    if create_resp.status_code in (200, 201):
        org_id = create_resp.json().get("id", create_resp.json().get("_id", "?"))
        print(f"  ✓ Organization '{ORG_NAME}' created (id={org_id})")
        return org_id
    else:
        print(f"  ✗ Failed to create org: {create_resp.status_code} – {create_resp.text}")
        sys.exit(1)


def ensure_analyst_user(client: httpx.Client, headers: dict, org_id: str) -> str:
    """Creates the analyst user in the agentix-lab org. Returns the generated API key."""
    print(f"\n[User] Checking analyst '{ANALYST_LOGIN}'...")

    # Check if user exists
    users_resp = client.get(f"{CORTEX_URL}/api/user", headers=headers)
    if users_resp.status_code == 200:
        users = users_resp.json() if isinstance(users_resp.json(), list) else []
        for u in users:
            if u.get("login") == ANALYST_LOGIN:
                uid = u.get("id", u.get("_id", "?"))
                print(f"  → User already exists (id={uid})")
                # Try to renew API key
                return renew_api_key(client, headers, uid)

    # Create user
    create_resp = client.post(
        f"{CORTEX_URL}/api/user",
        json={
            "login": ANALYST_LOGIN,
            "name": ANALYST_NAME,
            "roles": ANALYST_ROLES,
            "password": ANALYST_PASS,
            "organization": ORG_NAME,
        },
        headers=headers,
    )
    if create_resp.status_code in (200, 201):
        uid = create_resp.json().get("id", create_resp.json().get("_id", "?"))
        print(f"  ✓ Analyst user created (id={uid})")
        return renew_api_key(client, headers, uid)
    else:
        print(f"  ✗ Failed to create user: {create_resp.status_code} – {create_resp.text}")
        return ""


def renew_api_key(client: httpx.Client, headers: dict, user_id: str) -> str:
    """Generates or renews an API key for the given user."""
    key_resp = client.post(f"{CORTEX_URL}/api/user/{user_id}/key/renew", headers=headers)
    if key_resp.status_code in (200, 201):
        api_key = key_resp.text.strip().strip('"')
        print(f"  ✓ API key generated: {api_key[:8]}...{api_key[-4:]}")
        return api_key
    else:
        print(f"  → Could not generate API key: {key_resp.status_code}")
        return ""


def check_analyzers(client: httpx.Client, headers: dict):
    """Lists enabled analyzers and checks if VirusTotal is available."""
    print(f"\n[Analyzers] Checking available analyzers...")
    resp = client.get(f"{CORTEX_URL}/api/analyzer", headers=headers)
    if resp.status_code == 200:
        analyzers = resp.json() if isinstance(resp.json(), list) else []
        vt_analyzers = [a for a in analyzers if "VirusTotal" in a.get("name", "")]
        if vt_analyzers:
            print(f"  ✓ VirusTotal analyzers found:")
            for a in vt_analyzers:
                print(f"    • {a.get('name')} (id={a.get('id', '?')}, version={a.get('version', '?')})")
        else:
            print(f"  → No VirusTotal analyzers enabled yet.")
            print(f"    To enable: Cortex UI → Organization → Analyzers → VirusTotal_GetReport_3_1 → Enable")
            print(f"    Then add your VirusTotal API key in the analyzer settings.")
    else:
        print(f"  → Could not list analyzers: {resp.status_code}")


def update_env_file(api_key: str):
    """Appends/updates CORTEX_API_KEY in the .env file."""
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    env_path = os.path.normpath(env_path)

    if not api_key:
        print("\n[.env] Skipping .env update (no API key generated).")
        return

    print(f"\n[.env] Updating CORTEX_API_KEY in {env_path}...")
    try:
        with open(env_path, "r") as f:
            content = f.read()

        if "CORTEX_API_KEY=" in content:
            lines = content.splitlines()
            new_lines = []
            for line in lines:
                if line.startswith("CORTEX_API_KEY="):
                    new_lines.append(f"CORTEX_API_KEY={api_key}")
                else:
                    new_lines.append(line)
            with open(env_path, "w") as f:
                f.write("\n".join(new_lines) + "\n")
            print(f"  ✓ CORTEX_API_KEY updated in {env_path}")
        else:
            with open(env_path, "a") as f:
                f.write(f"\nCORTEX_API_KEY={api_key}\n")
            print(f"  ✓ CORTEX_API_KEY appended to {env_path}")

    except Exception as e:
        print(f"  ✗ Could not update .env: {e}")
        print(f"  → Set manually: CORTEX_API_KEY={api_key}")


def main():
    print("=" * 60)
    print("Agentix Cortex Setup")
    print("=" * 60)
    print(f"  Cortex URL: {CORTEX_URL}")

    # Quick connectivity check
    try:
        ping = httpx.get(f"{CORTEX_URL}/api/status", timeout=5.0)
        status_data = ping.json()
        print(f"  ✓ Cortex is reachable (status: {ping.status_code})")
        if "config" not in status_data and "versions" not in status_data:
            print(f"  → Cortex might not be fully initialised yet.")
    except Exception as e:
        print(f"  ✗ Cortex is not reachable at {CORTEX_URL}: {e}")
        print(f"    Make sure 'docker compose up cortex' is running.")
        sys.exit(1)

    with httpx.Client(timeout=15.0) as client:
        get_admin_token(client)
        auth_headers = {
            "Content-Type": "application/json",
        }

        org_id = ensure_organization(client, auth_headers)
        api_key = ensure_analyst_user(client, auth_headers, org_id)
        check_analyzers(client, auth_headers)

    update_env_file(api_key)

    print("\n" + "=" * 60)
    print("Cortex Setup Complete")
    print("=" * 60)
    print("""
Next Steps:
  1. Open Cortex UI: http://localhost:9001
  2. Login as the organization admin or super admin
  3. Go to: Organization → Analyzers → Find 'VirusTotal_GetReport_3_1'
  4. Click 'Enable' and configure:
       - api_key: <your VirusTotal API key>
       - polling_interval: 60
  5. Verify the API key works:
       uv run python scripts/simulate_attack.py --t1003
""")


if __name__ == "__main__":
    main()
