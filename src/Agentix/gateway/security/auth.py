import os
import hashlib
import jwt
from datetime import datetime, timedelta, timezone
from fastapi import Request, HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import asyncpg
import structlog
from pathlib import Path
from dotenv import load_dotenv

# Load settings and env
from agentic_common.settings import settings

logger = structlog.get_logger(__name__)

# JWT settings
JWT_SECRET = os.getenv("GATEWAY_JWT_SECRET", "dev-jwt-secret-key-1234567890-change-in-production")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("GATEWAY_ACCESS_TOKEN_EXPIRE_MINUTES", "1440")) # 24 hours

# Credentials configuration
DEFAULT_USERNAME = os.getenv("GATEWAY_USERNAME", "admin")
DEFAULT_PASSWORD = os.getenv("GATEWAY_PASSWORD", "admin123")

def hash_password(password: str, salt: bytes | None = None) -> str:
    """Hash a password securely using PBKDF2 (SHA256)."""
    if salt is None:
        salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )
    return salt.hex() + ":" + key.hex()

def verify_password(stored_password: str, provided_password: str) -> bool:
    """Verify a hashed password against a provided plain text password."""
    try:
        salt_hex, key_hex = stored_password.split(":")
        salt = bytes.fromhex(salt_hex)
        key = hashlib.pbkdf2_hmac(
            'sha256',
            provided_password.encode('utf-8'),
            salt,
            100000
        )
        return key.hex() == key_hex
    except Exception:
        return False

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Create a signed JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt

class AuthStore:
    """Handles PostgreSQL user authentication storage operations."""
    def __init__(self):
        self._pool = None
        self._table_name = "agentix_users"

    async def get_pool(self) -> asyncpg.Pool:
        if self._pool is None:
            # strip +asyncpg for asyncpg library DSN compatibility
            dsn = settings.agentix_postgres_url.replace("+asyncpg", "")
            logger.info("auth_store.connecting_db", dsn_masked=dsn.split("@")[-1])
            self._pool = await asyncpg.create_pool(dsn=dsn)
        return self._pool

    async def setup_db(self) -> None:
        """Create users table if not exists and seed default user."""
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            async with conn.transaction():
                # Create table
                await conn.execute(f"""
                    CREATE TABLE IF NOT EXISTS {self._table_name} (
                        id UUID PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        email TEXT,
                        role TEXT NOT NULL,
                        permissions JSONB,
                        created_at TIMESTAMP NOT NULL
                    )
                """)
                # Check if default user exists
                user_exists = await conn.fetchval(
                    f"SELECT EXISTS(SELECT 1 FROM {self._table_name} WHERE username = $1)",
                    DEFAULT_USERNAME
                )
                if not user_exists:
                    import uuid
                    user_id = uuid.uuid4()
                    pw_hash = hash_password(DEFAULT_PASSWORD)
                    await conn.execute(f"""
                        INSERT INTO {self._table_name} (id, username, password_hash, email, role, permissions, created_at)
                        VALUES ($1, $2, $3, $4, $5, $6, $7)
                    """, user_id, DEFAULT_USERNAME, pw_hash, f"{DEFAULT_USERNAME}@agentix.ai", "admin", "[]", datetime.now())
                    logger.info("auth_store.default_user_seeded", username=DEFAULT_USERNAME)

    async def get_user_by_username(self, username: str) -> dict | None:
        """Fetch user by username from database."""
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                f"SELECT id, username, password_hash, email, role, permissions FROM {self._table_name} WHERE username = $1",
                username
            )
            if row:
                return dict(row)
        return None

    async def close(self) -> None:
        if self._pool:
            await self._pool.close()
            self._pool = None

# Singleton instance of AuthStore
auth_store = AuthStore()

security = HTTPBearer()

async def verify_jwt_token(credentials: HTTPAuthorizationCredentials = Security(security)) -> dict:
    """
    FastAPI Dependency to verify the local JWT token from the Authorization header.
    Returns the decoded token claims if valid.
    """
    token = credentials.credentials
    try:
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return decoded_token
    except jwt.ExpiredSignatureError as e:
        logger.warning("gateway.security.token_expired", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError as e:
        logger.error("gateway.security.token_verification_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_current_user(claims: dict = Security(verify_jwt_token)) -> dict:
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
        "role": claims.get("role", "user"),
        "permissions": claims.get("permissions", [])
    }
