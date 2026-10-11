"""Integration and unit tests for FastAPI REST and SSE endpoints in src/main.py.

Conforms to IEEE Access (Hmimou et al., 2025):
"A Multi-Agent System for Cybersecurity Threat Detection and Correlation Using Large Language Models"
"""

import json
from pathlib import Path
import sys
import pytest
from fastapi.testclient import TestClient

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

from src.main import app


@pytest.fixture(scope="module")
def client():
    """Provides a TestClient context with startup lifespan executed."""
    with TestClient(app) as test_client:
        yield test_client


class TestAPIEndpoints:
    """Test suite covering health, triage, streaming, benchmarks, and CORS."""

    def test_root_endpoint(self, client: TestClient):
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "docs_url" in data
        assert data["active_llm"] == "llama-3.3-70b-versatile"

    def test_health_endpoint(self, client: TestClient):
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["active_llm"] == "llama-3.3-70b-versatile"
        assert "vector_index" in data
        assert "status" in data["vector_index"]
        assert "paper_alignment" in data

    def test_benchmark_endpoint(self, client: TestClient):
        response = client.get("/api/v1/benchmark")
        assert response.status_code == 200
        data = response.json()
        assert "metadata" in data
        assert "published_benchmarks" in data
        assert "system_accuracy_pct" in data["published_benchmarks"]

    def test_cors_preflight(self, client: TestClient):
        headers = {
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type",
        }
        response = client.options("/api/v1/triage", headers=headers)
        assert response.status_code == 200
        assert response.headers.get("access-control-allow-origin") == "http://localhost:5173"
        assert response.headers.get("access-control-allow-credentials") == "true"

    def test_triage_empty_payload(self, client: TestClient):
        payload = {
            "email_text": "",
            "log_text": "",
            "target_network": "",
        }
        response = client.post("/api/v1/triage", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert "findings" in data
        assert len(data["findings"]) == 0
        assert data["correlation_result"] is not None
        assert data["correlation_result"]["incident_detected"] is False

    def test_triage_coordinated_attack(self, client: TestClient):
        payload = {
            "email_text": (
                "URGENT: Your account credentials have expired. "
                "Authenticate at http://192.168.1.105/auth or access will be revoked within 24 hours."
            ),
            "log_text": (
                "Oct 10 02:14:01 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22\n"
                "Oct 10 02:14:03 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22\n"
                "Oct 10 02:14:05 srv1 sshd[102]: Accepted password for root from 192.168.1.105 port 22\n"
                "Oct 10 02:14:10 srv1 sudo: pam_unix(sudo:session): session opened for user root by (uid=0)"
            ),
            "target_network": "192.168.1.105",
            "task_id": "TEST-TRIAGE-API-001",
        }
        response = client.post("/api/v1/triage", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["task_id"] == "TEST-TRIAGE-API-001"
        assert len(data["findings"]) == 3
        assert data["correlation_result"]["incident_detected"] is True
        assert data["correlation_result"]["threat_severity"] in ["HIGH", "CRITICAL"]
        assert "192.168.1.105" in data["correlation_result"]["common_artifacts"]["ips"]

    def test_stream_triage_sse_post(self, client: TestClient):
        payload = {
            "email_text": "URGENT: verify password at http://192.168.1.105/login within 24 hours",
            "log_text": "Oct 10 02:14:01 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22",
            "target_network": "192.168.1.105",
        }
        response = client.post("/api/v1/stream-triage", json=payload)
        assert response.status_code == 200
        assert "text/event-stream" in response.headers.get("content-type", "")

        # Parse SSE lines
        text = response.text
        lines = [line.strip() for line in text.split("\n") if line.strip().startswith("data:")]
        events = [json.loads(line[len("data:"):].strip()) for line in lines]

        # Verify presence of essential step events
        steps = [e.get("step") for e in events]
        assert "email_worker" in steps
        assert "log_worker" in steps
        assert "ip_worker" in steps
        assert "supervisor" in steps

        # Check completed events
        completed_email = next((e for e in events if e.get("step") == "email_worker" and e.get("status") == "completed"), None)
        assert completed_email is not None
        assert "data" in completed_email

        completed_sup = next((e for e in events if e.get("step") == "supervisor" and e.get("status") == "completed"), None)
        assert completed_sup is not None
        assert "data" in completed_sup

    def test_structured_error_handling(self, client: TestClient):
        # Sending completely invalid body (e.g. array instead of object)
        response = client.post("/api/v1/triage", content="invalid json")
        assert response.status_code == 422
        data = response.json()
        assert data.get("error") is True
        assert data.get("status_code") == 422
