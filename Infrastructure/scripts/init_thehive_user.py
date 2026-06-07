import os
import sys

import httpx
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

THEHIVE_URL = os.getenv("THEHIVE_URL", "http://localhost:9000")
THEHIVE_ADMIN_USER = "admin@thehive.local"
THEHIVE_ADMIN_PASS = "secret"
ANALYST_LOGIN = "analyst@thehive.local"
ANALYST_NAME = "SOC Analyst"
ANALYST_PROFILE = "soc-analyst"  # Will be created by setup_thehive.py or we default to analyst


def get_admin_headers(client: httpx.Client) -> dict:
    """Logs in as admin and returns session token headers."""
    print(f"  → Trying session login as {THEHIVE_ADMIN_USER}...")
    resp = client.post(
        f"{THEHIVE_URL}/api/login",
        json={"user": THEHIVE_ADMIN_USER, "password": THEHIVE_ADMIN_PASS},
    )
    if resp.status_code != 200:
        print(f"  ✗ Admin login failed: {resp.status_code} – {resp.text}")
        sys.exit(1)

    cookie = resp.headers.get("Set-Cookie", "")
    session_token = ""
    for part in cookie.split(";"):
        part = part.strip()
        if part.startswith("THEHIVE-SESSION="):
            session_token = part
            break

    if not session_token:
        print("  ✗ Could not extract session cookie from admin login.")
        sys.exit(1)

    print("  ✓ Admin session established.")
    return {"Cookie": session_token, "Content-Type": "application/json"}


def ensure_analyst_user(client: httpx.Client, admin_headers: dict) -> str:
    """Ensures the analyst user exists in TheHive. Returns user ID/login."""
    print(f"\n[User] Checking analyst '{ANALYST_LOGIN}'...")

    # 1. List users to see if analyst already exists
    # Try both /api/user and /api/v1/user
    resp = client.get(f"{THEHIVE_URL}/api/user", headers=admin_headers)
    if resp.status_code == 404:
        resp = client.get(f"{THEHIVE_URL}/api/v1/user", headers=admin_headers)

    if resp.status_code != 200:
        print(f"  ✗ Failed to list users: {resp.status_code} – {resp.text}")
        sys.exit(1)

    users = resp.json()
    analyst_user = None
    for u in users:
        if u.get("login") == ANALYST_LOGIN:
            analyst_user = u
            break

    if analyst_user:
        user_id = analyst_user.get("id", analyst_user.get("_id", ANALYST_LOGIN))
        print(f"  → User already exists (id={user_id})")
        return user_id

    # 2. Check if custom profile exists, otherwise fallback
    profile_resp = client.get(f"{THEHIVE_URL}/api/profile", headers=admin_headers)
    if profile_resp.status_code == 404:
        profile_resp = client.get(f"{THEHIVE_URL}/api/v1/profile", headers=admin_headers)

    profiles = profile_resp.json() if profile_resp.status_code == 200 else []
    profile_names = [p.get("name") for p in profiles]

    selected_profile = ANALYST_PROFILE
    if selected_profile not in profile_names:
        if "analyst" in profile_names:
            selected_profile = "analyst"
            print("  → Profile 'soc-analyst' not found. Using built-in 'analyst' profile.")
        else:
            print("  → Profile 'soc-analyst' not found. Will try to use 'soc-analyst' anyway.")

    # 3. Create user
    print(f"  → Creating analyst user with profile '{selected_profile}'...")
    create_payload = {
        "login": ANALYST_LOGIN,
        "name": ANALYST_NAME,
        "profile": selected_profile,
        "status": "Ok",
        "password": "secret",
    }

    # Try /api/user first, fallback to /api/v1/user
    create_resp = client.post(
        f"{THEHIVE_URL}/api/user",
        json=create_payload,
        headers=admin_headers,
    )
    if create_resp.status_code == 404:
        create_resp = client.post(
            f"{THEHIVE_URL}/api/v1/user",
            json=create_payload,
            headers=admin_headers,
        )

    if create_resp.status_code in (200, 201):
        user_data = create_resp.json()
        user_id = user_data.get("id", user_data.get("_id", ANALYST_LOGIN))
        # 4. Set password explicitly
        client.patch(f"{THEHIVE_URL}/api/user/{ANALYST_LOGIN}", json={"password": "secret"}, headers=admin_headers)
        print(f"  ✓ User '{ANALYST_LOGIN}' created successfully (id={user_id})")
        return user_id
    else:
        print(f"  ✗ Failed to create user: {create_resp.status_code} – {create_resp.text}")
        sys.exit(1)


def renew_analyst_key(client: httpx.Client, admin_headers: dict, user_id: str) -> str:
    """Renews/generates the API key for the analyst user."""
    print(f"\n[API Key] Generating API key for user '{user_id}'...")

    # Try both /api/user/{user_id}/key/renew and /api/v1/user/{user_id}/key/renew
    renew_resp = client.post(
        f"{THEHIVE_URL}/api/user/{user_id}/key/renew",
        headers=admin_headers,
    )
    if renew_resp.status_code == 404:
        renew_resp = client.post(
            f"{THEHIVE_URL}/api/v1/user/{user_id}/key/renew",
            headers=admin_headers,
        )

    if renew_resp.status_code in (200, 201):
        # Depending on TheHive version, it might return JSON or plain text
        try:
            key_data = renew_resp.json()
            api_key = key_data.get("key") or key_data.get("apiKey") or renew_resp.text.strip().strip('"')
        except Exception:
            api_key = renew_resp.text.strip().strip('"')
        print(f"  ✓ API key generated successfully: {api_key}")
        return api_key
    else:
        print(f"  ✗ Failed to generate API key: {renew_resp.status_code} – {renew_resp.text}")
        sys.exit(1)


def main():
    print("=== TheHive Analyst User Initialization ===")
    print(f"Target: {THEHIVE_URL}")

    # Verify TheHive connectivity
    try:
        httpx.get(f"{THEHIVE_URL}/api/v1/status", timeout=5.0)
    except Exception:
        # Try /api/status or similar
        pass

    with httpx.Client(timeout=10.0) as client:
        admin_headers = get_admin_headers(client)
        user_id = ensure_analyst_user(client, admin_headers)
        renew_analyst_key(client, admin_headers, user_id)

    print("\n=== Initialization Complete ===")


if __name__ == "__main__":
    main()
