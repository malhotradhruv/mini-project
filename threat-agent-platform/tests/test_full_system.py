"""Comprehensive Full System Test Suite for Swarm Architecture, Persistence & Auth.

Conforms to IEEE Access (Hmimou et al., 2025):
"A Multi-Agent System for Cybersecurity Threat Detection and Correlation Using Large Language Models"

Validates:
1. Single-device session revocation logic and token rotation.
2. Database persistence of war-room dialogues, specialist findings, and incidents.
3. Swarm cyclic termination without infinite execution loops across attack and benign flows.
4. Correct entity linking across disparate telemetry items (Email, Syslog, Network Recon).
"""

import sys
import uuid
import datetime
from pathlib import Path
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
    IncidentRecord,
    WarRoomMessage,
    SpecialistFindingRecord,
)
from src.core.auth import AuthService
from src.core.swarm_graph import build_cyber_warroom_swarm

try:
    import pytest_asyncio
    async_fixture = pytest_asyncio.fixture
except ImportError:
    async_fixture = pytest.fixture

TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


@async_fixture
async def async_db():
    """In-memory async SQLite test session fixture."""
    engine = create_async_engine(TEST_DB_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    Session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with Session() as session:
        yield session
    await engine.dispose()


@pytest.mark.asyncio
async def test_single_device_session_revocation(async_db: AsyncSession):
    """Verifies that logging in from Device 2 revokes Device 1's active token."""
    # 1. Register User with Device Alpha
    pwd_hash = AuthService.get_password_hash("testpass123")
    user = User(username="analyst_test", password_hash=pwd_hash, active_device_token="device_alpha")
    async_db.add(user)
    await async_db.commit()

    # 2. Login from Device Beta
    login_res = await AuthService.authenticate_user(async_db, "analyst_test", "testpass123", "device_beta")
    assert "access_token" in login_res
    assert login_res["token_type"] == "bearer"

    # 3. Check DB to ensure active_device_token updated
    await async_db.refresh(user)
    assert user.active_device_token == "device_beta"
    assert user.active_device_token != "device_alpha"


@pytest.mark.asyncio
async def test_db_persistence_dialogues_and_incidents(async_db: AsyncSession):
    """Verifies relational database persistence of incidents, dialogues, and findings."""
    inc_id = str(uuid.uuid4())
    now_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # 1. Create Incident Record
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
    async_db.add(incident)
    await async_db.commit()

    # 2. Attach War Room Messages
    msg1 = WarRoomMessage(
        incident_id=inc_id,
        sender="EmailHunter",
        recipient="LeadSupervisor",
        action_type="OBSERVE",
        content="Phishing URL detected with target host 192.168.1.105",
        artifacts={"ips": ["192.168.1.105"]},
        timestamp=now_ts,
    )
    msg2 = WarRoomMessage(
        incident_id=inc_id,
        sender="LeadSupervisor",
        recipient="BlueTeamCommander",
        action_type="DELEGATE",
        content="Lock down host 192.168.1.105 immediately",
        artifacts={},
        timestamp=now_ts,
    )
    async_db.add_all([msg1, msg2])

    # 3. Attach Specialist Findings
    finding = SpecialistFindingRecord(
        incident_id=inc_id,
        agent_id="LogForensics",
        is_malicious=True,
        confidence=0.92,
        summary="SSH brute force burst detected",
        technical_indicators=["3 failed SSH authentications from 192.168.1.105"],
    )
    async_db.add(finding)
    await async_db.commit()

    # 4. Query and Verify Relationships
    stmt = select(IncidentRecord).where(IncidentRecord.id == inc_id)
    res = await async_db.execute(stmt)
    retrieved = res.scalar_one_or_none()

    assert retrieved is not None
    assert retrieved.id == inc_id
    assert retrieved.severity == "CRITICAL"
    assert len(retrieved.messages) == 2
    assert retrieved.messages[0].sender == "EmailHunter"
    assert len(retrieved.findings) == 1
    assert retrieved.findings[0].agent_id == "LogForensics"
    assert retrieved.findings[0].is_malicious is True
    assert "192.168.1.105" in retrieved.containment_commands[0]


@pytest.mark.asyncio
async def test_swarm_execution_cycle():
    """Verifies the cyclic swarm reaches consensus and terminates properly on attack flow."""
    swarm = build_cyber_warroom_swarm()
    state = {
        "task_id": str(uuid.uuid4()),
        "raw_email_stream": "URGENT: Reset credentials at http://192.168.1.105/auth",
        "raw_log_stream": (
            "Oct 11 02:14:01 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22\n"
            "Oct 11 02:14:03 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22\n"
            "Oct 11 02:14:06 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22"
        ),
        "target_cidr": "192.168.1.105",
        "messages": [],
        "specialist_findings": [],
        "next_speaker": "supervisor",
        "iteration_count": 0,
        "max_iterations": 8,
        "consensus_reached": False,
        "final_incident_report": None,
    }

    result = await swarm.ainvoke(state)
    assert len(result["messages"]) >= 4
    assert result["consensus_reached"] is True
    assert result["final_incident_report"] is not None
    assert result["final_incident_report"].incident_active is True
    assert "192.168.1.105" in result["final_incident_report"].containment_commands[0]


@pytest.mark.asyncio
async def test_swarm_cyclic_termination_benign():
    """Verifies the cyclic swarm terminates cleanly without recursion loops on benign flow."""
    swarm = build_cyber_warroom_swarm()
    state = {
        "task_id": str(uuid.uuid4()),
        "raw_email_stream": "Quarterly company newsletter: Celebrating engineering wins.",
        "raw_log_stream": "Oct 11 09:00:01 srv1 systemd[1]: Started Daily apt upgrade and clean activities.",
        "target_cidr": "10.0.0.50",
        "messages": [],
        "specialist_findings": [],
        "next_speaker": "supervisor",
        "iteration_count": 0,
        "max_iterations": 8,
        "consensus_reached": False,
        "final_incident_report": None,
    }

    result = await swarm.ainvoke(state)
    assert result["consensus_reached"] is True
    assert result["final_incident_report"] is not None
    assert result["final_incident_report"].incident_active is False
    assert result["final_incident_report"].threat_severity == "BENIGN"


@pytest.mark.asyncio
async def test_entity_linking_across_telemetry():
    """Verifies that the swarm correctly links shared entities across email, log, and recon."""
    swarm = build_cyber_warroom_swarm()
    target_ip = "192.168.1.105"
    state = {
        "task_id": str(uuid.uuid4()),
        "raw_email_stream": f"URGENT: Re-authenticate to node http://{target_ip}/portal immediately.",
        "raw_log_stream": (
            f"Oct 11 02:14:01 srv1 sshd[102]: Failed password for root from {target_ip} port 22\n"
            f"Oct 11 02:14:04 srv1 sshd[102]: Failed password for root from {target_ip} port 22"
        ),
        "target_cidr": target_ip,
        "messages": [],
        "specialist_findings": [],
        "next_speaker": "supervisor",
        "iteration_count": 0,
        "max_iterations": 8,
        "consensus_reached": False,
        "final_incident_report": None,
    }

    result = await swarm.ainvoke(state)
    report = result["final_incident_report"]
    assert report is not None

    # Verify IP is linked across specialist findings and report entities
    findings = result.get("specialist_findings", [])
    extracted_ips = set()
    for f in findings:
        for ip in f.extracted_entities.get("ips", []):
            extracted_ips.add(ip)

    assert target_ip in extracted_ips
    assert target_ip in report.correlated_entities.get("ips", [])
    assert target_ip in report.root_cause_analysis
