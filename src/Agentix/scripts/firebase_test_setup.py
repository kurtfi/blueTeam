import os
import sys
from pathlib import Path
import firebase_admin
from firebase_admin import credentials, auth
from dotenv import load_dotenv

# Add src/Agentix to sys.path
root_dir = Path(__file__).resolve().parent.parent
sys.path.append(str(root_dir))

# Load .env
load_dotenv(root_dir / ".env")

def setup_test_users():
    cred_path = os.getenv("FIREBASE_CREDENTIALS")
    if not cred_path:
        print("FIREBASE_CREDENTIALS not found in .env")
        return

    # Handle relative path
    if not os.path.isabs(cred_path):
        cred_path = str(root_dir / cred_path)

    if not os.path.exists(cred_path):
        print(f"Credentials file not found at {cred_path}")
        return

    if not firebase_admin._apps:
        cred = credentials.Certificate(cred_path)
        firebase_admin.initialize_app(cred)
        print("Firebase Admin initialized.")

    users = [
        {
            "email": "test_user@agentix.ai",
            "password": "Password123!",
            "display_name": "Test User",
            "claims": {"role": "user", "permissions": ["read", "chat"]}
        },
        {
            "email": "test_admin@agentix.ai",
            "password": "AdminPassword123!",
            "display_name": "Test Admin",
            "claims": {"role": "admin", "permissions": ["read", "chat", "manage"]}
        }
    ]

    for user_data in users:
        email = user_data["email"]
        try:
            # Check if user exists
            user = auth.get_user_by_email(email)
            print(f"User {email} already exists. Updating...")
            auth.update_user(
                user.uid,
                display_name=user_data["display_name"]
            )
        except auth.UserNotFoundError:
            print(f"Creating user {email}...")
            user = auth.create_user(
                email=email,
                password=user_data["password"],
                display_name=user_data["display_name"]
            )
        
        # Set custom claims
        auth.set_custom_user_claims(user.uid, user_data["claims"])
        print(f"Set custom claims for {email}: {user_data['claims']}")
        print(f"UID: {user.uid}")
        print("-" * 20)

if __name__ == "__main__":
    setup_test_users()
