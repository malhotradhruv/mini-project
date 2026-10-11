"""Comprehensive automated test suite for Threat Agent Platform.

Conforms to IEEE Access (Hmimou et al., 2025):
"A Multi-Agent System for Cybersecurity Threat Detection and Correlation Using Large Language Models"

Validates:
1. Schema & Model Validation (TaskInput, AgentReport, ExtractedEntities).
2. Email Agent Deterministic & Offline Fallbacks (dnspython NXDOMAIN handling, TextBlob urgency, FAISS empty vs stored).
3. Log Agent Pattern & Boundary Tests (Clean syslogs, Brute-force burst, Sudo privilege escalation).
4. IP Agent & NVD API Offline Resilience (ipaddress invalid input interception, NVD timeout / 403 fallback).
5. Entity Correlator Logic Tests (Isolated disjoint events vs Correlated multi-stage events).
"""

from pathlib import Path
import sys
from unittest.mock import MagicMock, patch

import pytest
import requests
from pydantic import ValidationError

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

from src.models.schemas import (
    AgentReport,
    CorrelatedIncident,
    ExtractedEntities,
    TaskInput,
)
from src.utils.vector_store import VectorStoreManager
from src.utils.nvd_client import NVDClient
from src.agents.email_agent import EmailAgent
from src.agents.log_agent import LogAgent
from src.agents.ip_agent import IPAgent
from src.core.dispatcher import TaskDispatcher
from src.core.correlator import ContextualCorrelator, ThreatCorrelator


# =============================================================================
# PYTEST FIXTURES
# =============================================================================

@pytest.fixture(scope="session")
def index_path() -> Path:
    """Path to pre-seeded FAISS index."""
    return PROJECT_ROOT / "data" / "indices" / "faiss_email_index.bin"


@pytest.fixture(scope="session")
def populated_vector_store(index_path: Path) -> VectorStoreManager:
    """Populated VectorStoreManager instance with pre-seeded templates."""
    store = VectorStoreManager()
    if index_path.exists():
        store.load(index_path)
    return store


@pytest.fixture(scope="function")
def empty_vector_store() -> VectorStoreManager:
    """Empty VectorStoreManager instance without indexed templates."""
    store = VectorStoreManager()
    store.texts = []
    store.metadatas = []
    if store.index is not None and hasattr(store.index, "reset"):
        store.index.reset()
    return store


@pytest.fixture(scope="session")
def email_agent(populated_vector_store: VectorStoreManager) -> EmailAgent:
    """EmailAgent instance with populated vector store."""
    return EmailAgent(vector_store=populated_vector_store)


@pytest.fixture(scope="session")
def log_agent() -> LogAgent:
    """LogAgent instance."""
    return LogAgent()


@pytest.fixture(scope="session")
def ip_agent() -> IPAgent:
    """IPAgent instance."""
    return IPAgent()


@pytest.fixture(scope="session")
def correlator() -> ContextualCorrelator:
    """ContextualCorrelator instance."""
    return ContextualCorrelator()


# =============================================================================
# SUITE 1: SCHEMA & MODEL VALIDATION TESTS
# =============================================================================

class TestSchemaAndModelValidation:
    """Validates strict Pydantic v2 schemas and data contract boundaries."""

    def test_task_input_rejects_empty_and_unsupported_types(self):
        """Verify TaskInput rejects empty task types or unsupported values."""
        # Unsupported task type string
        with pytest.raises(ValidationError):
            TaskInput(task_type="unsupported", payload="test payload")  # type: ignore

        # Empty string task type
        with pytest.raises(ValidationError):
            TaskInput(task_type="", payload="test payload")  # type: ignore

        # Arbitrary non-contract domain
        with pytest.raises(ValidationError):
            TaskInput(task_type="malware_binary", payload="test payload")  # type: ignore

        # Empty payload
        with pytest.raises(ValidationError):
            TaskInput(task_type="email", payload="")

        # Valid permutations must initialize cleanly
        for valid_type in ["email", "log", "ip"]:
            task = TaskInput(task_type=valid_type, payload="legitimate content payload")
            assert task.task_type == valid_type
            assert task.payload == "legitimate content payload"

    def test_agent_report_strictly_enforces_risk_score_interval(self):
        """Verify AgentReport strictly enforces risk_score within [0.0, 1.0]."""
        # Valid boundary scores
        rep_zero = AgentReport(
            agent_id="test_agent",
            is_malicious=False,
            risk_score=0.0,
            explanation="Zero risk assessment",
        )
        assert rep_zero.risk_score == 0.0

        rep_one = AgentReport(
            agent_id="test_agent",
            is_malicious=True,
            risk_score=1.0,
            explanation="Maximum risk assessment",
        )
        assert rep_one.risk_score == 1.0

        rep_mid = AgentReport(
            agent_id="test_agent",
            is_malicious=True,
            risk_score=0.75,
            explanation="Elevated threat assessment",
        )
        assert rep_mid.risk_score == 0.75

        # Scores strictly exceeding 1.0 must be rejected
        with pytest.raises(ValidationError):
            AgentReport(
                agent_id="test_agent",
                is_malicious=True,
                risk_score=1.01,
                explanation="Out of bounds above",
            )

        with pytest.raises(ValidationError):
            AgentReport(
                agent_id="test_agent",
                is_malicious=True,
                risk_score=99.9,
                explanation="Large score out of bounds",
            )

        # Scores below 0.0 must be rejected
        with pytest.raises(ValidationError):
            AgentReport(
                agent_id="test_agent",
                is_malicious=False,
                risk_score=-0.05,
                explanation="Negative score out of bounds",
            )

    def test_extracted_entities_parsing_and_type_integrity(self):
        """Verify ExtractedEntities parses IP lists, domain lists, and ports without type corruption."""
        entities = ExtractedEntities(
            ips=["192.168.1.1", "10.0.0.1", "192.168.1.1"],  # includes duplicate
            domains=["portal.top", "target.corp", "portal.top"],  # includes duplicate
            timestamps=["03:12:01", "03:12:05"],
            ports=[80, 443, 22, 80],  # includes duplicate
        )

        # Assert deduplication preserving elements
        assert entities.ips == ["192.168.1.1", "10.0.0.1"]
        assert entities.domains == ["portal.top", "target.corp"]
        assert entities.ports == [22, 80, 443]

        # Verify type preservation
        assert all(isinstance(ip, str) for ip in entities.ips)
        assert all(isinstance(d, str) for d in entities.domains)
        assert all(isinstance(p, int) for p in entities.ports)

        # Port out-of-range bounds checks
        with pytest.raises(ValidationError):
            ExtractedEntities(ports=[70000])

        with pytest.raises(ValidationError):
            ExtractedEntities(ports=[-1])

        with pytest.raises(ValidationError):
            ExtractedEntities(ports=["invalid_port"])  # type: ignore


# =============================================================================
# SUITE 2: EMAIL AGENT DETERMINISTIC & OFFLINE FALLBACK TESTS
# =============================================================================

class TestEmailAgentDeterministicAndOfflineFallbacks:
    """Validates deterministic email regex extraction, DNS forensics, and FAISS RAG lookups."""

    def test_dns_checker_handles_unresolvable_domains_without_exception(self, email_agent: EmailAgent):
        """Test with valid and non-existent garbage domains without raising unhandled NXDOMAIN."""
        test_domains = [
            "this-domain-does-not-exist-at-all-1234.xyz",
            "completely-nonexistent-domain-xyz99999.invalid",
            "localhost",
        ]

        # Verify _check_dns catches NXDOMAIN and unresolved DNS errors safely
        dns_results = email_agent._check_dns(test_domains)
        assert len(dns_results) == len(test_domains)

        for res in dns_results:
            assert "domain" in res
            assert "is_anomalous" in res
            assert "anomaly_reason" in res

        # Check that the unresolvable garbage domain was flagged as anomalous
        garbage_record = next(r for r in dns_results if r["domain"] == "this-domain-does-not-exist-at-all-1234.xyz")
        assert garbage_record["is_anomalous"] is True
        assert any(term in str(garbage_record["anomaly_reason"]) for term in ["NXDOMAIN", "Unresolved", "failure"])

        # End-to-end analyze method with unresolvable domain
        sample_email = (
            "URGENT: Please verify your account credentials: "
            "http://this-domain-does-not-exist-at-all-1234.xyz/auth "
            "within 24 hours."
        )
        report = email_agent.analyze(sample_email)
        assert isinstance(report, AgentReport)
        assert any("DNS Forensics" in ind for ind in report.technical_indicators)

    def test_urgency_token_and_sentiment_extraction(self, email_agent: EmailAgent):
        """Verify TextBlob and regex accurately extract urgency tokens ('suspend', 'immediately', 'verify account')."""
        urgency_payload = (
            "URGENT SECURITY ALERT: We will suspend your account immediately unless you verify account credentials!"
        )

        audit = email_agent._analyze_urgency_and_sentiment(urgency_payload)
        matched = audit["matched_cues"]

        assert "suspend" in matched
        assert "immediately" in matched
        assert "verify account" in matched
        assert audit["cue_count"] >= 3

        # Verify TextBlob sentiment analysis metrics
        assert "polarity" in audit
        assert "subjectivity" in audit
        assert isinstance(audit["polarity"], float)
        assert isinstance(audit["subjectivity"], float)

        # Analyze report must compile Urgency Forensics into technical indicators
        report = email_agent.analyze(urgency_payload)
        assert any("Urgency Forensics" in ind for ind in report.technical_indicators)

    def test_faiss_empty_vs_stored_vector_query_behavior(
        self,
        empty_vector_store: VectorStoreManager,
        populated_vector_store: VectorStoreManager,
    ):
        """Test FAISS query behavior on empty vs. stored vector index without memory faults."""
        query = "URGENT: Your Office 365 account has been suspended! Please verify immediately."

        # 1. Querying an empty vector index must return empty list safely
        empty_results = empty_vector_store.search_similarity(query, top_k=3)
        assert isinstance(empty_results, list)
        assert len(empty_results) == 0

        # 2. Querying a populated vector index must return ranked matches
        stored_results = populated_vector_store.search_similarity(query, top_k=3)
        assert isinstance(stored_results, list)
        assert len(stored_results) > 0

        top_match = stored_results[0]
        assert "text" in top_match
        assert "similarity_score" in top_match
        assert "metadata" in top_match
        assert "distance" in top_match

        # Normalized similarity score bounded between 0.0 and 1.0
        assert 0.0 <= top_match["similarity_score"] <= 1.0
        assert top_match["similarity_score"] > 0.40


# =============================================================================
# SUITE 3: LOG AGENT PATTERN & BOUNDARY TESTS
# =============================================================================

class TestLogAgentPatternAndBoundaryChecks:
    """Validates behavioral log parsing, brute-force velocity, and privilege escalation audits."""

    def test_clean_syslog_zero_anomalies(self, log_agent: LogAgent):
        """Provide clean syslog entries with zero anomalies; verify is_malicious is False and risk <= 0.2."""
        clean_logs = (
            "Oct 10 09:14:02 srv-bastion-01 sshd[15001]: Accepted publickey for alice from 10.0.1.50 port 51220 ssh2: RSA SHA256:validkey123\n"
            "Oct 10 09:15:00 srv-bastion-01 CRON[15020]: (root) CMD (/usr/local/bin/backup_database.sh > /dev/null 2>&1)\n"
            "Oct 10 09:16:10 srv-bastion-01 systemd[1]: Started Daily log rotation service.\n"
            "Oct 10 09:20:00 srv-bastion-01 pam_unix(sshd:session): session closed for user alice\n"
            "Oct 10 09:25:00 srv-bastion-01 ntpd[982]: synchronized to 169.254.169.123: offset +0.000122 sec"
        )

        report = log_agent.analyze(clean_logs)
        assert isinstance(report, AgentReport)
        assert report.is_malicious is False
        assert report.risk_score <= 0.2
        assert report.raw_evidence["brute_force_events"] == []
        assert report.raw_evidence["privilege_escalation_events"] == []
        assert not any("Brute Force" in ind for ind in report.technical_indicators)

    def test_brute_force_burst_detection(self, log_agent: LogAgent):
        """Provide a brute-force burst (5 failed SSH password attempts); verify count, IP, and heuristic."""
        offending_ip = "198.51.100.42"
        burst_logs = (
            f"Oct 10 03:12:01 sshd[14021]: Failed password for invalid user admin from {offending_ip} port 48210 ssh2\n"
            f"Oct 10 03:12:01 sshd[14022]: Failed password for invalid user root from {offending_ip} port 48212 ssh2\n"
            f"Oct 10 03:12:01 sshd[14024]: Failed password for deploy from {offending_ip} port 48216 ssh2\n"
            f"Oct 10 03:12:01 sshd[14026]: Failed password for deploy from {offending_ip} port 48220 ssh2\n"
            f"Oct 10 03:12:01 sshd[14028]: Failed password for deploy from {offending_ip} port 48224 ssh2\n"
        )

        report = log_agent.analyze(burst_logs)
        assert isinstance(report, AgentReport)
        assert report.is_malicious is True
        assert offending_ip in report.entities.ips

        # Offending IP failed attempt count recorded
        failed_counts = report.raw_evidence["failed_attempts_by_ip"]
        assert failed_counts.get(offending_ip) == 5

        # Offending brute-force heuristic flag identified
        assert any("Brute Force Detected" in ind for ind in report.technical_indicators)
        assert any(offending_ip in flag for flag in report.raw_evidence["brute_force_events"])

    def test_sudo_privilege_escalation_detection(self, log_agent: LogAgent):
        """Test logs with sudo failure lines; verify privilege escalation markers are added."""
        priv_esc_logs = (
            "Oct 10 04:00:10 srv-web sudo: guest : user NOT in sudoers ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/sh\n"
            "Oct 10 05:15:00 srv-bastion sudo: deploy : 3 incorrect password attempts ; TTY=pts/0 ; COMMAND=/bin/bash\n"
            "Oct 10 05:20:00 srv-bastion su[14035]: FAILED SU (to root) deploy on pts/0"
        )

        report = log_agent.analyze(priv_esc_logs)
        assert isinstance(report, AgentReport)
        assert report.is_malicious is True
        assert report.risk_score >= 0.50

        # Privilege escalation markers identified in technical indicators
        assert any("Privilege Escalation" in ind for ind in report.technical_indicators)
        assert len(report.raw_evidence["privilege_escalation_events"]) > 0


# =============================================================================
# SUITE 4: IP AGENT & NVD API OFFLINE RESILIENCE TESTS
# =============================================================================

class TestIPAgentAndNVDApiOfflineResilience:
    """Validates network profiling, ipaddress validation interception, and NVD API fallback resilience."""

    def test_invalid_ip_notations_intercepted_without_crashing(self, ip_agent: IPAgent):
        """Test IPAgent against invalid IP notations; verify ipaddress validation intercepts cleanly."""
        invalid_ip_inputs = [
            "999.999.1.1",
            "not_an_ip",
            "256.100.0.1",
            "invalid.hostname.target",
            "192.168.1.300",
        ]

        for bad_ip in invalid_ip_inputs:
            report = ip_agent.analyze(bad_ip)
            assert isinstance(report, AgentReport)
            assert report.is_malicious is False
            assert report.risk_score == 0.0
            assert any("INPUT_REJECTED" in ind for ind in report.technical_indicators)
            assert report.entities.ips == []
            assert report.raw_evidence.get("status") == "malformed_input"

    def test_nvd_api_offline_fallback_on_network_timeout(self):
        """Simulate NVD API HTTP timeout; verify client falls back to cached CVE dictionaries."""
        nvd_client = NVDClient(timeout=2)

        # Mock requests.Session.get raising Timeout
        with patch.object(
            nvd_client.session,
            "get",
            side_effect=requests.exceptions.Timeout("Connection timed out to services.nvd.nist.gov"),
        ):
            # Known service query under timeout
            cves = nvd_client.query_service_vulnerabilities("ssh", port=22)
            assert isinstance(cves, list)
            assert len(cves) > 0
            assert any(c["id"] == "CVE-2024-6387" for c in cves)

            # Explicit CVE query under timeout
            cve_record = nvd_client.query_cve("CVE-2024-6387")
            assert cve_record is not None
            assert cve_record["id"] == "CVE-2024-6387"
            assert cve_record["cvss_score"] >= 7.0

    def test_nvd_api_offline_fallback_on_http_403_forbidden(self):
        """Simulate NVD API rate-limit/403 status; verify client falls back cleanly without exception."""
        nvd_client = NVDClient(timeout=2)

        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.json.return_value = {"message": "Rate limit exceeded"}

        with patch.object(nvd_client.session, "get", return_value=mock_resp):
            cves = nvd_client.query_service_vulnerabilities("http", port=80)
            assert isinstance(cves, list)
            assert len(cves) > 0
            assert any(c["id"] == "CVE-2021-41773" for c in cves)

            cve_bluekeep = nvd_client.query_cve("CVE-2019-0708")
            assert cve_bluekeep is not None
            assert cve_bluekeep["id"] == "CVE-2019-0708"


# =============================================================================
# SUITE 5: ENTITY CORRELATOR LOGIC TESTS
# =============================================================================

class TestEntityCorrelatorLogic:
    """Validates contextual threat correlation, exact set intersections, and false-positive suppression."""

    def test_isolated_event_disjoint_telemetry_suppression(self, correlator: ContextualCorrelator):
        """Pass two AgentReports with completely disjoint IPs and domains.

        Assert: incident_detected == False, confidence_score <= 0.2, and attack_timeline is empty.
        """
        rep_email = AgentReport(
            agent_id="email_agent",
            is_malicious=True,
            risk_score=0.85,
            entities=ExtractedEntities(ips=["192.0.2.1"], domains=["phish-isolated-vector.top"]),
            technical_indicators=["Isolated phishing link with credential form"],
            raw_evidence={},
            explanation="Phishing email lure targeting employee inbox.",
        )
        rep_log = AgentReport(
            agent_id="log_agent",
            is_malicious=True,
            risk_score=0.80,
            entities=ExtractedEntities(ips=["198.51.100.99"], domains=["internal-server.local"]),
            technical_indicators=["Failed login sequence on unrelated internal host"],
            raw_evidence={},
            explanation="Unrelated authentication warning.",
        )

        incident = correlator.correlate([rep_email, rep_log])

        assert isinstance(incident, CorrelatedIncident)
        assert incident.incident_detected is False
        assert incident.confidence_score <= 0.2
        assert incident.attack_timeline == []
        assert "suppressed" in incident.narrative.lower() or "disjoint" in incident.narrative.lower()

    def test_correlated_event_shared_ip_escalation(self, correlator: ContextualCorrelator):
        """Pass three AgentReports where email, log, and IP scan share '192.168.1.105'.

        Assert: incident_detected == True, confidence_score >= 0.8, and '192.168.1.105' in correlated_entities.ips.
        """
        shared_pivot_ip = "192.168.1.105"

        rep_email = AgentReport(
            agent_id="email_agent",
            is_malicious=True,
            risk_score=0.90,
            entities=ExtractedEntities(ips=[shared_pivot_ip], domains=["update-internal-patch.top"]),
            technical_indicators=[f"Phishing link referencing target IP {shared_pivot_ip}"],
            raw_evidence={},
            explanation="Spear-phishing lure staged from internal pivot target.",
        )
        rep_log = AgentReport(
            agent_id="log_agent",
            is_malicious=True,
            risk_score=0.95,
            entities=ExtractedEntities(ips=[shared_pivot_ip], timestamps=["03:12:01", "03:12:05"]),
            technical_indicators=[
                f"High-velocity SSH brute force from {shared_pivot_ip}",
                "Unauthorized sudo pipe to bash execution",
            ],
            raw_evidence={},
            explanation="Authentication brute force followed by privilege escalation.",
        )
        rep_ip = AgentReport(
            agent_id="ip_agent",
            is_malicious=True,
            risk_score=0.85,
            entities=ExtractedEntities(ips=[shared_pivot_ip], ports=[22, 80]),
            technical_indicators=["Critical CVE-2024-6387 identified on port 22"],
            raw_evidence={},
            explanation="Exposed perimeter host with unpatched High/Critical vulnerabilities.",
        )

        incident = correlator.correlate([rep_email, rep_log, rep_ip])

        assert isinstance(incident, CorrelatedIncident)
        assert incident.incident_detected is True
        assert incident.confidence_score >= 0.8
        assert shared_pivot_ip in incident.correlated_entities.ips
        assert len(incident.attack_timeline) > 0
        assert len(incident.remediation_steps) > 0
        assert any(shared_pivot_ip in step for step in incident.remediation_steps)


# =============================================================================
# CLI RUNNER ENTRYPOINT
# =============================================================================

if __name__ == "__main__":
    pytest.main(["-v", __file__])
