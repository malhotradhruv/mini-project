"""Unit tests for LangGraph ThreatState and Pydantic v2 contract models.

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
    ExtractedArtifacts,
    AgentFinding,
    AttackStage,
    CorrelatedIncidentReport,
    ThreatState,
    create_initial_threat_state,
)


class TestExtractedArtifacts:
    """Tests for ExtractedArtifacts data model."""

    def test_default_empty_lists(self):
        artifacts = ExtractedArtifacts()
        assert artifacts.ips == []
        assert artifacts.domains == []
        assert artifacts.urls == []
        assert artifacts.ports == []
        assert artifacts.cves == []
        assert artifacts.timestamps == []

    def test_populated_artifacts(self):
        artifacts = ExtractedArtifacts(
            ips=["192.168.1.105", "10.0.0.1"],
            domains=["evil-domain.top"],
            urls=["http://evil-domain.top/auth"],
            ports=[22, 80],
            cves=["CVE-2024-6387"],
            timestamps=["02:14:01", "02:14:03"],
        )
        assert len(artifacts.ips) == 2
        assert artifacts.domains == ["evil-domain.top"]
        assert artifacts.ports == [22, 80]
        assert artifacts.cves == ["CVE-2024-6387"]


class TestAgentFinding:
    """Tests for AgentFinding data model."""

    def test_valid_agent_finding(self):
        finding = AgentFinding(
            agent_id="EmailAgent",
            is_malicious=True,
            risk_score=0.85,
            artifacts=ExtractedArtifacts(ips=["192.168.1.105"]),
            indicators=["PHISHING_PATTERN_MATCH", "DNS_NXDOMAIN"],
            raw_evidence={"dns": "NXDOMAIN"},
            analyst_summary="High-risk phishing lure targeting corporate credentials.",
        )
        assert finding.agent_id == "EmailAgent"
        assert finding.is_malicious is True
        assert finding.risk_score == 0.85
        assert len(finding.indicators) == 2

    def test_risk_score_interval_boundaries(self):
        # Valid lower and upper bounds
        f_low = AgentFinding(
            agent_id="LogAgent",
            is_malicious=False,
            risk_score=0.0,
            analyst_summary="Clean log traffic.",
        )
        assert f_low.risk_score == 0.0

        f_high = AgentFinding(
            agent_id="LogAgent",
            is_malicious=True,
            risk_score=1.0,
            analyst_summary="Confirmed brute force attack.",
        )
        assert f_high.risk_score == 1.0

        # Below 0.0 must raise ValidationError
        with pytest.raises(ValidationError):
            AgentFinding(
                agent_id="LogAgent",
                is_malicious=False,
                risk_score=-0.1,
                analyst_summary="Invalid.",
            )

        # Above 1.0 must raise ValidationError
        with pytest.raises(ValidationError):
            AgentFinding(
                agent_id="LogAgent",
                is_malicious=True,
                risk_score=1.05,
                analyst_summary="Invalid.",
            )


class TestAttackStage:
    """Tests for AttackStage data model."""

    def test_valid_attack_stage(self):
        stage = AttackStage(
            stage_number=1,
            tactic="Initial Access",
            description="Spear-phishing email delivered to employee inbox.",
            correlated_indicator="http://update-internal-patch.top/hotfix.exe",
        )
        assert stage.stage_number == 1
        assert stage.tactic == "Initial Access"
        assert "Spear-phishing" in stage.description
        assert stage.correlated_indicator == "http://update-internal-patch.top/hotfix.exe"


class TestCorrelatedIncidentReport:
    """Tests for CorrelatedIncidentReport data model."""

    def test_default_values(self):
        report = CorrelatedIncidentReport()
        assert report.incident_detected is False
        assert report.threat_severity == "LOW"
        assert report.confidence_score == 0.0
        assert report.participating_agents == []
        assert report.attack_timeline == []
        assert report.containment_playbook == []

    def test_escalated_incident_report(self):
        report = CorrelatedIncidentReport(
            incident_detected=True,
            threat_severity="CRITICAL",
            confidence_score=0.98,
            participating_agents=["EmailAgent", "LogAgent", "IPAgent"],
            common_artifacts=ExtractedArtifacts(ips=["192.168.1.105"]),
            attack_timeline=[
                AttackStage(
                    stage_number=1,
                    tactic="Initial Access",
                    description="Phishing lure",
                    correlated_indicator="192.168.1.105",
                ),
            ],
            forensic_narrative="Coordinated multi-vector attack detected sharing pivot IP 192.168.1.105.",
            containment_playbook=["Block IP 192.168.1.105 at edge firewalls."],
        )
        assert report.incident_detected is True
        assert report.threat_severity == "CRITICAL"
        assert len(report.participating_agents) == 3
        assert len(report.containment_playbook) == 1

    def test_confidence_score_validation(self):
        with pytest.raises(ValidationError):
            CorrelatedIncidentReport(confidence_score=-0.2)

        with pytest.raises(ValidationError):
            CorrelatedIncidentReport(confidence_score=1.5)


class TestThreatStateAndLangGraph:
    """Tests for TypedDict ThreatState container and LangGraph integration."""

    def test_create_initial_threat_state(self):
        state = create_initial_threat_state(
            task_id="TASK-001",
            raw_email="URGENT: Click here",
            raw_logs="Oct 10 sshd: failed login",
            target_network="192.168.1.105",
        )
        assert state["task_id"] == "TASK-001"
        assert state["raw_email"] == "URGENT: Click here"
        assert state["findings"] == []
        assert state["correlation_result"] is None
        assert state["audit_trace"] == []

    def test_langgraph_execution_with_threat_state(self):
        from langgraph.graph import StateGraph, START, END

        # Define simple worker nodes appending findings and audit messages
        def email_node(state: ThreatState):
            finding = AgentFinding(
                agent_id="EmailAgent",
                is_malicious=True,
                risk_score=0.9,
                artifacts=ExtractedArtifacts(ips=["192.168.1.105"]),
                analyst_summary="Phishing lure identified.",
            )
            return {
                "findings": [finding],
                "audit_trace": ["EmailAgent executed forensics"],
            }

        def log_node(state: ThreatState):
            finding = AgentFinding(
                agent_id="LogAgent",
                is_malicious=True,
                risk_score=0.95,
                artifacts=ExtractedArtifacts(ips=["192.168.1.105"]),
                analyst_summary="Brute force activity identified.",
            )
            return {
                "findings": [finding],
                "audit_trace": ["LogAgent executed forensics"],
            }

        def correlator_node(state: ThreatState):
            incident = CorrelatedIncidentReport(
                incident_detected=True,
                threat_severity="HIGH",
                confidence_score=0.92,
                participating_agents=[f.agent_id for f in state["findings"]],
            )
            return {
                "correlation_result": incident,
                "audit_trace": ["Correlator finished cross-vector synthesis"],
            }

        graph = StateGraph(ThreatState)
        graph.add_node("email_agent", email_node)
        graph.add_node("log_agent", log_node)
        graph.add_node("correlator", correlator_node)

        graph.add_edge(START, "email_agent")
        graph.add_edge("email_agent", "log_agent")
        graph.add_edge("log_agent", "correlator")
        graph.add_edge("correlator", END)

        workflow = graph.compile()
        initial_state = create_initial_threat_state(task_id="E2E-TEST")
        final_state = workflow.invoke(initial_state)

        # Verify operator.add reducer accumulated both findings
        assert len(final_state["findings"]) == 2
        agent_ids = [f.agent_id for f in final_state["findings"]]
        assert "EmailAgent" in agent_ids
        assert "LogAgent" in agent_ids

        # Verify operator.add reducer accumulated audit trace
        assert len(final_state["audit_trace"]) == 3
        assert "EmailAgent executed forensics" in final_state["audit_trace"]
        assert "LogAgent executed forensics" in final_state["audit_trace"]
        assert "Correlator finished cross-vector synthesis" in final_state["audit_trace"]

        # Verify correlation result was populated
        assert final_state["correlation_result"] is not None
        assert final_state["correlation_result"].incident_detected is True
        assert final_state["correlation_result"].threat_severity == "HIGH"
