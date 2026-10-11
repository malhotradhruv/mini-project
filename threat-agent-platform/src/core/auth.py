"""Single-Device JWT Authentication & Cryptographic Session Lock.

Conforms to IEEE Access (Hmimou et al., 2025):
"A Multi-Agent System for Cybersecurity Threat Detection and Correlation Using Large Language Models"

Enforces:
1. Strong password hashing via passlib bcrypt context.
2. Signed JWT tokens with embedded device_id claims.
3. Single-Device Session Lock: Logging in from Device B updates the database token,
   automatically revoking and invalidating Device A's session.
"""

import os
import uuid
import datetime
from typing import Optional, Dict, Any
from passlib.context import CryptContext
from jose import jwt, JWTError
from fastapi import HTTPException, Security, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from src.db.models import User
from src.db.session import get_db

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "sentinel_soc_super_secret_key_2026")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "480"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()


def _get_utc_now() -> datetime.datetime:
    """Returns timezone-aware UTC datetime."""
    return datetime.datetime.now(datetime.timezone.utc)


class AuthService:
    """Authentication and cryptographic token operations."""

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verifies plain text password against bcrypt hash."""
        return pwd_context.verify(plain_password, hashed_password)

    @staticmethod
    def get_password_hash(password: str) -> str:
        """Generates bcrypt password hash."""
        return pwd_context.hash(password)

    @staticmethod
    def create_access_token(data: dict, device_id: str) -> str:
        """Creates a signed JWT with expiration and bound device_id claim."""
        to_encode = data.copy()
        expire = _get_utc_now() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        to_encode.update({"exp": expire, "device_id": device_id})
        return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    @staticmethod
    async def authenticate_user(
        db: AsyncSession, username: str, password: str, device_id: str
    ) -> Dict[str, Any]:
        """Authenticates user credentials and binds the session to the new device_id."""
        stmt = select(User).where(User.username == username)
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()

        if not user or not AuthService.verify_password(password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password",
            )

        # Single-device lock: Update user record with the new device_id token
        new_device_token = device_id or str(uuid.uuid4())
        user.active_device_token = new_device_token
        user.last_login = _get_utc_now()
        await db.commit()

        token = AuthService.create_access_token(
            {"sub": user.username, "role": user.role},
            device_id=new_device_token,
        )
        return {
            "access_token": token,
            "token_type": "bearer",
            "role": user.role,
            "username": user.username,
        }


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(security),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Validates JWT bearer token and enforces the single-device database lock."""
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: Optional[str] = payload.get("sub")
        device_id: Optional[str] = payload.get("device_id")
        if not username or not device_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
            )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )

    stmt = select(User).where(User.username == username)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    # Single-Device Validation: Ensure active token matches what is stored in DB
    if user.active_device_token != device_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Session revoked: Account logged in from another device/browser.",
        )

    return user


def require_role(required_role: str):
    """Dependency factory checking operator authorization role."""
    async def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role != required_role and current_user.role != "ADMIN":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation requires {required_role} privileges.",
            )
        return current_user

    return role_checker


__all__ = [
    "AuthService",
    "get_current_user",
    "require_role",
    "SECRET_KEY",
    "ALGORITHM",
    "ACCESS_TOKEN_EXPIRE_MINUTES",
]
