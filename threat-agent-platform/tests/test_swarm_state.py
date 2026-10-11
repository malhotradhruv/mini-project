"""Unit tests for the autonomous cyclic SwarmState and multi-agent protocols.

Conforms to IEEE Access (Hmimou et al., 2025):
"A Multi-Agent System for Cybersecurity Threat Detection and Correlation Using Large Language Models"
"""

import operator
from pathlib import Path
import sys
import pytest
from pydantic import ValidationError

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

from src.core.state import (
    AgentMessage,
    MitreTechnique,
    AgentFinding,
    AdversaryHypothesis,
    SwarmIncidentReport,
    SwarmState,
    create_initial_swarm_state,
    ExtractedArtifacts,
)


class TestAgentMessage:
    """Validation for inter-agent war-room message exchanges."""

    def test_valid_agent_message(self):
        msg = AgentMessage(
            sender="EmailHunter",
            recipient="ALL",
            content="Discovered credential harvesting link in spear-phishing lure.",
            action_type="OBSERVE",
            artifacts={"ips": ["192.168.1.105"], "url": "http://192.168.1.105/patch.php"},
            timestamp="2026-10-11T15:30:00Z",
        )
        assert msg.sender == "EmailHunter"
        assert msg.recipient == "ALL"
        assert msg.action_type == "OBSERVE"
        assert "192.168.1.105" in msg.artifacts["ips"]

    def test_delegation_action_type(self):
        msg = AgentMessage(
            sender="LeadSupervisor",
            recipient="LogForensics",
            content="Verify if IP 192.168.1.105 performed failed authentication bursts.",
            action_type="DELEGATE",
            artifacts={"target_ip": "192.168.1.105"},
            timestamp="2026-10-11T15:30:05Z",
        )
        assert msg.action_type == "DELEGATE"
        assert msg.recipient == "LogForensics"

    def test_invalid_action_type_rejection(self):
        with pytest.raises(ValidationError):
            AgentMessage(
                sender="EmailHunter",
                content="Test",
                action_type="INVALID_ACTION",  # Must be one of DELEGATE, OBSERVE, CHALLENGE, VERIFY, CONSENSUS
                timestamp="2026-10-11T15:30:00Z",
            )


class TestMitreTechnique:
    """Validation for MITRE ATT&CK taxonomy tags."""

    def test_valid_technique(self):
        tech = MitreTechnique(
            technique_id="T1566.002",
            tactic="Initial Access",
            description="Spearphishing Link",
        )
        assert tech.technique_id == "T1566.002"
        assert tech.tactic == "Initial Access"


class TestAgentFinding:
    """Validation for individual specialist forensic findings."""

    def test_valid_finding_with_swarm_schema(self):
        finding = AgentFinding(
            agent_id="NetworkRecon",
            is_malicious=True,
            confidence_score=0.95,
            mitre_tags=[
                MitreTechnique(
                    technique_id="T1190",
                    tactic="Initial Access",
                    description="Exploit Public-Facing Application",
                )
            ],
            technical_indicators=["High severity vulnerability on Apache 2.4.49: CVE-2021-41773 (CVSS 9.8)"],
            extracted_entities={"ips": ["192.168.1.105"], "ports": ["80"], "cves": ["CVE-2021-41773"], "domains": []},
            raw_evidence={"service": "Apache 2.4.49"},
            summary="Remote path traversal detected.",
        )
        assert finding.agent_id == "NetworkRecon"
        assert finding.confidence_score == 0.95
        assert len(finding.mitre_tags) == 1
        assert finding.mitre_tags[0].technique_id == "T1190"
        # Verify backward compatibility properties
        assert finding.risk_score == 0.95
        assert finding.analyst_summary == "Remote path traversal detected."
        assert len(finding.indicators) == 1
        assert "192.168.1.105" in finding.artifacts.ips

    def test_confidence_score_bounds(self):
        with pytest.raises(ValidationError):
            AgentFinding(
                agent_id="TestAgent",
                is_malicious=True,
                confidence_score=1.5,  # Exceeds 1.0
                summary="Invalid score test",
            )
        with pytest.raises(ValidationError):
            AgentFinding(
                agent_id="TestAgent",
                is_malicious=True,
                confidence_score=-0.1,  # Sub-zero
                summary="Negative score test",
            )

    def test_legacy_kwargs_bridge(self):
        """Ensure findings initialized with legacy parameters bridge cleanly."""
        legacy_finding = AgentFinding(
            agent_id="EmailAgent",
            is_malicious=True,
            risk_score=0.88,
            artifacts=ExtractedArtifacts(ips=["192.0.2.1"], urls=["http://192.0.2.1/login.php"]),
            indicators=["Urgency cue: '24 hours'"],
            analyst_summary="Spear-phishing lure detected.",
        )
        assert legacy_finding.confidence_score == 0.88
        assert legacy_finding.summary == "Spear-phishing lure detected."
        assert "Urgency cue: '24 hours'" in legacy_finding.technical_indicators
        assert "192.0.2.1" in legacy_finding.extracted_entities["ips"]


class TestAdversaryHypothesis:
    """Validation for Red-Team predictive adversarial trajectory simulation."""

    def test_valid_adversary_hypothesis(self):
        hyp = AdversaryHypothesis(
            predicted_next_step="Attempt remote code execution via Apache path traversal followed by interactive reverse shell.",
            target_asset="192.168.1.105 (Web Server)",
            mitre_tactic="Execution",
            exploit_vector="CVE-2021-41773",
        )
        assert hyp.target_asset == "192.168.1.105 (Web Server)"
        assert hyp.mitre_tactic == "Execution"
        assert hyp.exploit_vector == "CVE-2021-41773"


class TestSwarmIncidentReport:
    """Validation for autonomous swarm consolidated reports."""

    def test_valid_incident_report(self):
        report = SwarmIncidentReport(
            incident_active=True,
            threat_severity="CRITICAL",
            consensus_confidence=0.96,
            root_cause_analysis="Coordinated multi-vector campaign linking spear-phishing, SSH brute-force, and web exploit.",
            correlated_entities={"ips": ["192.168.1.105"], "ports": ["22", "80"]},
            adversary_trajectory=AdversaryHypothesis(
                predicted_next_step="Internal pivot to database tier",
                target_asset="10.0.0.50 (DB Cluster)",
                mitre_tactic="Lateral Movement",
                exploit_vector="Credential Reuse",
            ),
            containment_commands=[
                "iptables -A INPUT -s 192.168.1.105 -j DROP",
                "systemctl restart sshd",
            ],
        )
        assert report.incident_active is True
        assert report.threat_severity == "CRITICAL"
        assert report.consensus_confidence == 0.96
        assert len(report.containment_commands) == 2
        assert report.adversary_trajectory.mitre_tactic == "Lateral Movement"


class TestSwarmState:
    """Validation for the cyclic LangGraph swarm state machine."""

    def test_initial_state_factory(self):
        state = create_initial_swarm_state(
            task_id="SWARM-001",
            raw_email_stream="URGENT: patch required",
            raw_log_stream="Failed password for root",
            target_cidr="192.168.1.0/24",
            max_iterations=6,
        )
        assert state["task_id"] == "SWARM-001"
        assert state["next_speaker"] == "LeadSupervisor"
        assert state["iteration_count"] == 0
        assert state["max_iterations"] == 6
        assert state["consensus_reached"] is False
        assert state["messages"] == []
        assert state["specialist_findings"] == []
        assert state["final_incident_report"] is None

    def test_operator_add_message_reducer(self):
        """Verify operator.add appends war-room messages without overwriting."""
        msg1 = AgentMessage(
            sender="LeadSupervisor",
            content="Initiating investigation.",
            action_type="DELEGATE",
            timestamp="2026-10-11T15:30:00Z",
        )
        msg2 = AgentMessage(
            sender="EmailHunter",
            content="Phishing confirmed.",
            action_type="OBSERVE",
            timestamp="2026-10-11T15:30:05Z",
        )
        # Simulate LangGraph operator.add reducer
        reduced_messages = operator.add([msg1], [msg2])
        assert len(reduced_messages) == 2
        assert reduced_messages[0].sender == "LeadSupervisor"
        assert reduced_messages[1].sender == "EmailHunter"
