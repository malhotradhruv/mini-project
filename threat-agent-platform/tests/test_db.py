"""Unit tests for SQLAlchemy async database models and session layer.

Conforms to IEEE Access (Hmimou et al., 2025):
"A Multi-Agent System for Cybersecurity Threat Detection and Correlation Using Large Language Models"
"""

import asyncio
import os
import uuid
from pathlib import Path
import sys
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

from src.db.models import (
    Base,
    User,
    IngestedSource,
    IncidentRecord,
    WarRoomMessage,
    SpecialistFindingRecord,
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


class TestDatabaseModels:
    """Tests for persistent storage models."""

    def test_user_creation_and_device_lock(self, test_db_session):
        session_factory, _ = test_db_session

        async def _run():
            async with session_factory() as session:
                user = User(
                    username="analyst_alice",
                    password_hash="argon2id_hash_placeholder",
                    role="ANALYST",
                    active_device_token="device_token_xyz_123",
                )
                session.add(user)
                await session.commit()
                await session.refresh(user)

                assert user.id is not None
                assert user.username == "analyst_alice"
                assert user.role == "ANALYST"
                assert user.active_device_token == "device_token_xyz_123"

                # Single-device token rotation
                user.active_device_token = "new_device_token_abc_456"
                await session.commit()
                await session.refresh(user)
                assert user.active_device_token == "new_device_token_abc_456"

        asyncio.run(_run())

    def test_ingested_source_tracking(self, test_db_session):
        session_factory, _ = test_db_session

        async def _run():
            async with session_factory() as session:
                src_id = str(uuid.uuid4())
                source = IngestedSource(
                    id=src_id,
                    source_type="IMAP_EMAIL",
                    raw_content="From: attacker@malicious.top\nSubject: Account Expired",
                    processed=False,
                )
                session.add(source)
                await session.commit()

                stmt = select(IngestedSource).where(IngestedSource.id == src_id)
                res = await session.execute(stmt)
                retrieved = res.scalar_one_or_none()

                assert retrieved is not None
                assert retrieved.source_type == "IMAP_EMAIL"
                assert retrieved.processed is False

                retrieved.processed = True
                await session.commit()

        asyncio.run(_run())

    def test_incident_record_with_messages_and_findings(self, test_db_session):
        session_factory, _ = test_db_session

        async def _run():
            async with session_factory() as session:
                inc_id = str(uuid.uuid4())
                incident = IncidentRecord(
                    id=inc_id,
                    severity="CRITICAL",
                    confidence_score=0.94,
                    root_cause="Multi-stage intrusion coordinated through IP: 192.168.1.105",
                    correlated_entities={"ips": ["192.168.1.105"], "ports": [22, 80]},
                    containment_commands=[
                        "iptables -A INPUT -s 192.168.1.105 -j DROP",
                        "fail2ban-client set sshd banip 192.168.1.105",
                    ],
                )
                session.add(incident)
                await session.commit()

                # Add WarRoomMessage
                msg = WarRoomMessage(
                    incident_id=inc_id,
                    sender="EmailHunter",
                    recipient="LeadSupervisor",
                    action_type="OBSERVE",
                    content="Discovered phishing domain login-portal.top",
                    artifacts={"ips": ["192.168.1.105"]},
                    timestamp="2026-10-11T12:00:00Z",
                )
                session.add(msg)

                # Add SpecialistFindingRecord
                finding = SpecialistFindingRecord(
                    incident_id=inc_id,
                    agent_id="NetworkRecon",
                    is_malicious=True,
                    confidence=0.91,
                    summary="Discovered unpatched CVEs on target",
                    technical_indicators=["Port 80 (Apache 2.4.49): CVE-2021-41773 (CVSS 7.5)"],
                )
                session.add(finding)
                await session.commit()

                # Query with relationships
                stmt = select(IncidentRecord).where(IncidentRecord.id == inc_id)
                res = await session.execute(stmt)
                retrieved_inc = res.scalar_one_or_none()

                assert retrieved_inc is not None
                assert retrieved_inc.severity == "CRITICAL"
                assert len(retrieved_inc.messages) == 1
                assert retrieved_inc.messages[0].sender == "EmailHunter"
                assert len(retrieved_inc.findings) == 1
                assert retrieved_inc.findings[0].agent_id == "NetworkRecon"
                assert len(retrieved_inc.containment_commands) == 2

        asyncio.run(_run())

    def test_session_lifecycle(self):
        from src.db.session import init_db, get_db

        async def _run():
            await init_db()
            async for session in get_db():
                assert isinstance(session, AsyncSession)
                # Verify can query User table
                res = await session.execute(select(User))
                assert res is not None
                break

        asyncio.run(_run())

