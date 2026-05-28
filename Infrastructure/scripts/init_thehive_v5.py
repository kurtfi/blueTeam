import os
import sys
import httpx
from dotenv import load_dotenv

load_dotenv()

THEHIVE_URL = os.getenv("THEHIVE_URL", "http://localhost:9000")
THEHIVE_ADMIN_USER = "admin@thehive.local"
THEHIVE_ADMIN_PASS = "secret"
ANALYST_LOGIN = "analyst@thehive.local"
ANALYST_NAME = "SOC Analyst"
ORG_NAME = "asdg"

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

def ensure_organisation(client: httpx.Client, admin_headers: dict) -> str:
    """Ensures the organization exists in TheHive. Returns org ID/name."""
    print(f"\n[Org] Checking organisation '{ORG_NAME}'...")
    resp = client.get(f"{THEHIVE_URL}/api/organisation", headers=admin_headers)
    if resp.status_code == 200:
        orgs = resp.json()
        for org in orgs:
            if org.get("name") == ORG_NAME:
                print(f"  → Organisation '{ORG_NAME}' already exists.")
                return ORG_NAME
                
    # Create organisation
    print(f"  → Creating organisation '{ORG_NAME}'...")
    create_resp = client.post(
        f"{THEHIVE_URL}/api/organisation",
        json={"name": ORG_NAME, "description": "SOC Operations Organisation"},
        headers=admin_headers,
    )
    if create_resp.status_code in (200, 201):
        print(f"  ✓ Organisation '{ORG_NAME}' created successfully.")
        return ORG_NAME
    else:
        print(f"  ✗ Failed to create organisation: {create_resp.status_code} – {create_resp.text}")
        sys.exit(1)

def create_or_update_user(client: httpx.Client, admin_headers: dict) -> str:
    """Creates or updates the analyst user with the correct organization mapping."""
    print(f"\n[User] Ensuring user '{ANALYST_LOGIN}' exists...")
    
    # 1. Check if user exists
    resp = client.get(f"{THEHIVE_URL}/api/user", headers=admin_headers)
    users = resp.json() if resp.status_code == 200 else []
    user_exists = False
    for u in users:
        if u.get("login") == ANALYST_LOGIN:
            user_exists = True
            break
            
    if not user_exists:
        # Create user
        print(f"  → Creating analyst user...")
        create_payload = {
            "login": ANALYST_LOGIN,
            "name": ANALYST_NAME,
            "status": "Ok",
            "password": "secret"
        }
        create_resp = client.post(
            f"{THEHIVE_URL}/api/user",
            json=create_payload,
            headers=admin_headers,
        )
        if create_resp.status_code not in (200, 201):
            print(f"  ✗ Failed to create user: {create_resp.status_code} – {create_resp.text}")
            sys.exit(1)
        print("  ✓ User created successfully.")
    else:
        print("  → User already exists.")

    # 2. Make sure user is unlocked/active and set password
    client.patch(
        f"{THEHIVE_URL}/api/user/{ANALYST_LOGIN}",
        json={"status": "Ok", "password": "secret"},
        headers=admin_headers
    )

    # 3. Map user to both organizations via PUT /api/v1/user/{userId}/organisations
    print(f"  → Mapping user to 'admin' (read-only) and 'asdg' (org-admin)...")
    org_payload = {
        "organisations": [
            {"organisation": "admin", "profile": "read-only"},
            {"organisation": "asdg", "profile": "org-admin"}
        ]
    }
    org_resp = client.put(
        f"{THEHIVE_URL}/api/v1/user/{ANALYST_LOGIN}/organisations",
        json=org_payload,
        headers=admin_headers
    )
    if org_resp.status_code == 200:
        print("  ✓ Organisation mapping updated successfully.")
    else:
        print(f"  ✗ Failed to update organisation mapping: {org_resp.status_code} – {org_resp.text}")
        sys.exit(1)

    # 4. Set default organisation to 'asdg' via PATCH
    print(f"  → Setting default organisation to 'asdg'...")
    patch_payload = {
        "defaultOrganisation": "asdg"
    }
    patch_resp = client.patch(
        f"{THEHIVE_URL}/api/user/{ANALYST_LOGIN}",
        json=patch_payload,
        headers=admin_headers
    )
    if patch_resp.status_code == 200:
        print("  ✓ Default organisation set to 'asdg'.")
    else:
        print(f"  ✗ Failed to set default organisation: {patch_resp.status_code} – {patch_resp.text}")

    return ANALYST_LOGIN

def renew_analyst_key(client: httpx.Client, admin_headers: dict, user_id: str) -> str:
    """Renews/generates the API key for the analyst user."""
    print(f"\n[API Key] Generating API key for user '{user_id}'...")
    renew_resp = client.post(
        f"{THEHIVE_URL}/api/user/{user_id}/key/renew",
        headers=admin_headers,
    )
    if renew_resp.status_code in (200, 201):
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
    print("=== TheHive v5 Advanced Initialization ===")
    print(f"Target: {THEHIVE_URL}")
    
    with httpx.Client(timeout=15.0) as client:
        admin_headers = get_admin_headers(client)
        ensure_organisation(client, admin_headers)
        user_id = create_or_update_user(client, admin_headers)
        api_key = renew_analyst_key(client, admin_headers, user_id)
        
    print("\n=== Initialization Complete ===")

if __name__ == "__main__":
    main()
