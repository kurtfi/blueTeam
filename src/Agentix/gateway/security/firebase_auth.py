import os
import structlog
from pathlib import Path
from fastapi import Request, HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import firebase_admin
from firebase_admin import credentials, auth
from dotenv import load_dotenv

# Load .env from the project root (assuming gateway/security/firebase_auth.py)
root_dir = Path(__file__).resolve().parent.parent.parent
load_dotenv(root_dir / ".env")

logger = structlog.get_logger(__name__)

# Try to initialize Firebase Admin if credentials are provided in the environment
def init_firebase():
    if not firebase_admin._apps:
        try:
            # Assumes the service account key path is set in FIREBASE_CREDENTIALS
            firebase_cred_path = os.getenv("FIREBASE_CREDENTIALS")
            
            # Resolve relative path if necessary
            if firebase_cred_path and not os.path.isabs(firebase_cred_path):
                firebase_cred_path = str(root_dir / firebase_cred_path)

            if firebase_cred_path and os.path.exists(firebase_cred_path):
                cred = credentials.Certificate(firebase_cred_path)
                firebase_admin.initialize_app(cred)
                logger.info("gateway.security.firebase_initialized_with_cert", path=firebase_cred_path)
            else:
                # Initialize with default credentials
                firebase_admin.initialize_app()
                logger.info("gateway.security.firebase_initialized_default")
        except Exception as e:
            logger.warning("gateway.security.firebase_init_failed", error=str(e))

init_firebase()

security = HTTPBearer()

async def verify_firebase_token(credentials: HTTPAuthorizationCredentials = Security(security)):
    """
    FastAPI Dependency to verify the Firebase JWT token from the Authorization header.
    Returns the decoded token claims if valid.
    """
    token = credentials.credentials
    try:
        # Verify the token via Firebase Admin SDK with check_revoked=True
        decoded_token = auth.verify_id_token(token, check_revoked=True)
        return decoded_token
    except Exception as e:
        logger.error("gateway.security.token_verification_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_current_user(claims: dict = Security(verify_firebase_token)) -> dict:
    """
    Extracts the user info from the verified claims.
    """
    uid = claims.get("uid")
    if not uid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User ID not found in token",
        )
    
    return {
        "uid": uid,
        "email": claims.get("email"),
        "role": claims.get("role", "user"), # Example of extracting custom claims
        "permissions": claims.get("permissions", [])
    }
