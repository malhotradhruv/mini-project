"""Unit tests for Single-Device JWT Authentication & Cryptographic Session Lock.

Conforms to IEEE Access (Hmimou et al., 2025):
"A Multi-Agent System for Cybersecurity Threat Detection and Correlation Using Large Language Models"
"""

import asyncio
import os
import uuid
from pathlib import Path
import sys
import pytest
from fastapi import HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

from src.db.models import Base, User
from src.core.auth import (
    AuthService,
    get_current_user,
    SECRET_KEY,
    ALGORITHM,
)


@pytest.fixture
def test_db_session():
    """In-memory async SQLite engine fixture for isolated testing."""
    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    session_factory = async_sessionmaker(test_engine, expire_on_commit=False, class_=AsyncSession)

    async def _setup():
        async with test_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        return session_factory, test_engine

    return asyncio.run(_setup())


class TestAuthService:
    """Tests for AuthService hashing and token issuance."""

    def test_password_hashing_and_verification(self):
        plain = "SuperSecurePassword2026!"
        hashed = AuthService.get_password_hash(plain)

        assert hashed != plain
        assert AuthService.verify_password(plain, hashed) is True
        assert AuthService.verify_password("WrongPassword123", hashed) is False

    def test_access_token_creation(self):
        token = AuthService.create_access_token(
            {"sub": "analyst1", "role": "ANALYST"},
            device_id="browser_chrome_mac",
        )
        assert isinstance(token, str)
        assert len(token) > 20

    def test_authentication_invalid_credentials(self, test_db_session):
        session_factory, _ = test_db_session

        async def _run():
            async with session_factory() as session:
                # Non-existent user
                with pytest.raises(HTTPException) as exc_info:
                    await AuthService.authenticate_user(session, "ghost_user", "pass", "dev1")
                assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED

                # Existing user, wrong password
                user = User(
                    username="analyst_bob",
                    password_hash=AuthService.get_password_hash("CorrectPass123"),
                    role="ANALYST",
                )
                session.add(user)
                await session.commit()

                with pytest.raises(HTTPException) as exc_info:
                    await AuthService.authenticate_user(session, "analyst_bob", "WrongPass456", "dev1")
                assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED

        asyncio.run(_run())


class TestSingleDeviceSessionLock:
    """Tests for single-device active token enforcement."""

    def test_single_device_session_lock_revocation(self, test_db_session):
        session_factory, _ = test_db_session

        async def _run():
            async with session_factory() as session:
                # 1. Create User
                password = "AnalystSecretKey#2026"
                user = User(
                    username="lead_analyst",
                    password_hash=AuthService.get_password_hash(password),
                    role="ADMIN",
                )
                session.add(user)
                await session.commit()

                # 2. Login from Device A (e.g. Work Laptop)
                auth_a = await AuthService.authenticate_user(
                    session, "lead_analyst", password, device_id="device_laptop_work"
                )
                token_a = auth_a["access_token"]
                creds_a = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token_a)

                # Device A can access protected resources
                current_user_a = await get_current_user(creds_a, session)
                assert current_user_a.username == "lead_analyst"
                assert current_user_a.active_device_token == "device_laptop_work"

                # 3. Login from Device B (e.g. Home Desktop)
                auth_b = await AuthService.authenticate_user(
                    session, "lead_analyst", password, device_id="device_desktop_home"
                )
                token_b = auth_b["access_token"]
                creds_b = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token_b)

                # Device B can access protected resources
                current_user_b = await get_current_user(creds_b, session)
                assert current_user_b.username == "lead_analyst"
                assert current_user_b.active_device_token == "device_desktop_home"

                # 4. Device A attempts access with prior token -> MUST BE REVOKED (403)
                with pytest.raises(HTTPException) as exc_info:
                    await get_current_user(creds_a, session)

                assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
                assert "Session revoked" in exc_info.value.detail
                assert "another device" in exc_info.value.detail

        asyncio.run(_run())

    def test_invalid_and_tampered_token(self, test_db_session):
        session_factory, _ = test_db_session

        async def _run():
            async with session_factory() as session:
                tampered = HTTPAuthorizationCredentials(scheme="Bearer", credentials="invalid.jwt.token")
                with pytest.raises(HTTPException) as exc_info:
                    await get_current_user(tampered, session)
                assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED

        asyncio.run(_run())
