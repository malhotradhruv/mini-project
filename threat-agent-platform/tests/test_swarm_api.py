"""Integration and API tests for Swarm Orchestration, Authentication, and Ingestion in src/main.py.

Conforms to IEEE Access (Hmimou et al., 2025):
"A Multi-Agent System for Cybersecurity Threat Detection and Correlation Using Large Language Models"
"""

import pytest
import uuid
from fastapi.testclient import TestClient
from sqlalchemy import select

from src.main import app
from src.db.session import init_db, async_session
from src.db.models import User, IncidentRecord, WarRoomMessage, SpecialistFindingRecord


@pytest.fixture(scope="module")
def client():
    """Provides a TestClient context with startup lifespan executed."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="module")
def auth_headers(client: TestClient):
    """Registers and logs in a test analyst, returning authorization headers."""
    unique_user = f"analyst_{uuid.uuid4().hex[:6]}"
    reg_payload = {
        "username": unique_user,
        "password": "StrongPassword!123",
        "device_id": f"device-soc-{uuid.uuid4().hex[:6]}",
    }
    # Register
    r_reg = client.post("/api/v1/auth/register", json=reg_payload)
    assert r_reg.status_code == 200

    # Login
    r_login = client.post("/api/v1/auth/login", json=reg_payload)
    assert r_login.status_code == 200
    token_data = r_login.json()
    token = token_data["access_token"]

    return {
        "Authorization": f"Bearer {token}",
        "username": unique_user,
        "device_id": reg_payload["device_id"],
    }


class TestAuthenticationEndpoints:
    """Tests registration, login, and single-device security."""

    def test_register_new_user(self, client: TestClient):
        unique_user = f"user_{uuid.uuid4().hex[:6]}"
        payload = {
            "username": unique_user,
            "password": "SecretPassword!123",
            "device_id": "test-device-01",
        }
        res = client.post("/api/v1/auth/register", json=payload)
        assert res.status_code == 200
        assert res.json()["message"] == "User registered successfully"

    def test_register_duplicate_username_fails(self, client: TestClient):
        unique_user = f"dup_{uuid.uuid4().hex[:6]}"
        payload = {
            "username": unique_user,
            "password": "SecretPassword!123",
            "device_id": "test-device-01",
        }
        res1 = client.post("/api/v1/auth/register", json=payload)
        assert res1.status_code == 200

        res2 = client.post("/api/v1/auth/register", json=payload)
        assert res2.status_code == 400
        assert "already registered" in res2.json()["message"]

    def test_login_invalid_password(self, client: TestClient):
        unique_user = f"inv_{uuid.uuid4().hex[:6]}"
        client.post(
            "/api/v1/auth/register",
            json={"username": unique_user, "password": "CorrectPassword!1", "device_id": "dev1"},
        )
        res = client.post(
            "/api/v1/auth/login",
            json={"username": unique_user, "password": "WrongPassword!", "device_id": "dev1"},
        )
        assert res.status_code == 401


class TestIngestionEndpoints:
    """Tests live ingestion endpoints."""

    def test_unauthenticated_ingest_fails(self, client: TestClient):
        res = client.post("/api/v1/ingest/poll-email")
        assert res.status_code in [401, 403]

    def test_poll_email_authenticated(self, client: TestClient, auth_headers: dict):
        headers = {"Authorization": auth_headers["Authorization"]}
        res = client.post("/api/v1/ingest/poll-email", headers=headers)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert "data" in data

    def test_simulate_log_burst_authenticated(self, client: TestClient, auth_headers: dict):
        headers = {"Authorization": auth_headers["Authorization"]}
        res = client.post("/api/v1/ingest/simulate-log-burst", headers=headers)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert "message" in data

    def test_tail_logs_authenticated(self, client: TestClient, auth_headers: dict):
        headers = {"Authorization": auth_headers["Authorization"]}
        res = client.post("/api/v1/ingest/tail-logs", headers=headers)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert "data" in data


class TestSwarmOrchestrationAndPersistence:
    """Tests end-to-end autonomous swarm execution, DB persistence, and incident audit trails."""

    def test_unauthenticated_swarm_investigate_fails(self, client: TestClient):
        res = client.post("/api/v1/swarm/investigate", json={})
        assert res.status_code in [401, 403]

    def test_swarm_investigation_and_db_persistence(self, client: TestClient, auth_headers: dict):
        headers = {"Authorization": auth_headers["Authorization"]}
        payload = {
            "raw_email": (
                "From: attacker@evil-corp.com\n"
                "Subject: Urgent: Verify Password\n"
                "Please authenticate immediately at http://192.168.1.105/login or face account termination."
            ),
            "raw_logs": (
                "Oct 10 02:14:01 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22\n"
                "Oct 10 02:14:03 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22\n"
                "Oct 10 02:14:05 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22\n"
                "Oct 10 02:14:10 srv1 sudo: pam_unix(sudo:session): session opened for user root by (uid=0)"
            ),
            "target_cidr": "192.168.1.105",
        }

        res = client.post("/api/v1/swarm/investigate", json=payload, headers=headers)
        assert res.status_code == 200
        data = res.json()

        assert "task_id" in data
        task_id = data["task_id"]
        assert "messages" in data
        assert len(data["messages"]) > 0
        assert "specialist_findings" in data
        assert "report" in data
        assert data["report"] is not None

        # Verify DB Persistence via GET /api/v1/incidents
        r_list = client.get("/api/v1/incidents", headers=headers)
        assert r_list.status_code == 200
        incidents = r_list.json()
        assert any(inc["id"] == task_id for inc in incidents)

        # Verify single incident retrieval via GET /api/v1/incidents/{incident_id}
        r_single = client.get(f"/api/v1/incidents/{task_id}", headers=headers)
        assert r_single.status_code == 200
        single_inc = r_single.json()
        assert single_inc["id"] == task_id
        assert "containment_commands" in single_inc
        assert len(single_inc["messages"]) > 0
        assert len(single_inc["findings"]) > 0

    def test_get_nonexistent_incident_returns_404(self, client: TestClient, auth_headers: dict):
        headers = {"Authorization": auth_headers["Authorization"]}
        res = client.get("/api/v1/incidents/nonexistent-uuid-999", headers=headers)
        assert res.status_code == 404
