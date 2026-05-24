import os
import sys
import requests
from pathlib import Path
import firebase_admin
from firebase_admin import credentials, auth
from dotenv import load_dotenv

# Add src/Agentix to sys.path
root_dir = Path(__file__).resolve().parent.parent
sys.path.append(str(root_dir))

# Load .env
load_dotenv(root_dir / ".env")

def get_id_token(email):
    """
    Generates a Firebase ID Token for a given user.
    Requires FIREBASE_WEB_API_KEY in .env.
    """
    api_key = os.getenv("FIREBASE_WEB_API_KEY")
    if not api_key:
        print("ERROR: FIREBASE_WEB_API_KEY not found in .env")
        print("Please add it to your .env file. You can find it in Firebase Console -> Project Settings -> General.")
        return None

    cred_path = os.getenv("FIREBASE_CREDENTIALS")
    if not cred_path:
        print("FIREBASE_CREDENTIALS not found in .env")
        return None

    # Handle relative path
    if not os.path.isabs(cred_path):
        cred_path = str(root_dir / cred_path)

    if not firebase_admin._apps:
        cred = credentials.Certificate(cred_path)
        firebase_admin.initialize_app(cred)

    try:
        # 1. Get User UID
        user = auth.get_user_by_email(email)
        uid = user.uid
        print(f"User UID: {uid}")

        # 2. Create Custom Token
        custom_token = auth.create_custom_token(uid).decode("utf-8")
        print("Custom Token generated.")

        # 3. Exchange Custom Token for ID Token via REST API
        url = f"https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyCustomToken?key={api_key}"
        payload = {
            "token": custom_token,
            "returnSecureToken": True
        }
        
        response = requests.post(url, json=payload)
        response.raise_for_status()
        
        id_token = response.json().get("idToken")
        print("\nSUCCESS! Firebase ID Token (JWT):\n")
        print(id_token)
        print("\nYou can use this in your 'Authorization' header as: Bearer <token>")
        return id_token

    except Exception as e:
        print(f"Error: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response: {e.response.text}")
        return None

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Generate Firebase ID Token for testing")
    parser.add_argument("email", help="Email of the test user", default="test_user@agentix.ai", nargs="?")
    args = parser.parse_args()
    
    get_id_token(args.email)
