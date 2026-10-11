"""Unit tests for LangGraph supervisor correlation node (supervisor_correlation_node).

Conforms to IEEE Access (Hmimou et al., 2025):
"A Multi-Agent System for Cybersecurity Threat Detection and Correlation Using Large Language Models"
"""

import asyncio
from pathlib import Path
import sys
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

from src.core.state import (
    ThreatState,
    AgentFinding,
    ExtractedArtifacts,
    CorrelatedIncidentReport,
    create_initial_threat_state,
)
from src.core.correlator import supervisor_correlation_node
from src.agents.email_agent import email_agent_node
from src.agents.log_agent import log_agent_node
from src.agents.ip_agent import ip_agent_node


class TestSupervisorCorrelationNode:
    """Tests for supervisor_correlation_node."""

    def test_empty_findings(self):
        state = create_initial_threat_state(task_id="EMPTY-001")
        result = asyncio.run(supervisor_correlation_node(state))
        assert "correlation_result" in result
        assert result["correlation_result"].incident_detected is False
        assert any("No findings provided" in trace for trace in result["audit_trace"])

    def test_disjoint_isolated_events_suppression(self):
        """Zero intersection across agents -> Multi-stage alert suppressed."""
        f_email = AgentFinding(
            agent_id="EmailIntelligenceAgent",
            is_malicious=True,
            risk_score=0.9,
            artifacts=ExtractedArtifacts(ips=["192.0.2.1"], domains=["phish-site.top"]),
            indicators=["Phishing lure"],
            analyst_summary="Isolated phishing email.",
        )
        f_log = AgentFinding(
            agent_id="BehavioralLogAgent",
            is_malicious=False,
            risk_score=0.1,
            artifacts=ExtractedArtifacts(ips=["10.0.0.5"]),
            indicators=[],
            analyst_summary="Normal cron activities.",
        )
        f_ip = AgentFinding(
            agent_id="NetworkReconAgent",
            is_malicious=False,
            risk_score=0.0,
            artifacts=ExtractedArtifacts(ips=["127.0.0.1"]),
            indicators=[],
            analyst_summary="Localhost loopback.",
        )

        state: ThreatState = {
            "task_id": "DISJOINT-001",
            "raw_email": "phish",
            "raw_logs": "cron",
            "target_network": "127.0.0.1",
            "findings": [f_email, f_log, f_ip],
            "correlation_result": None,
            "audit_trace": [],
        }

        result = asyncio.run(supervisor_correlation_node(state))
        report: CorrelatedIncidentReport = result["correlation_result"]
        assert report.incident_detected is False
        assert report.threat_severity == "LOW"
        assert report.confidence_score <= 0.20
        assert report.attack_timeline == []
        assert any("False positive correlation prevented" in trace for trace in result["audit_trace"])

    def test_coordinated_multi_stage_campaign_shared_ip(self):
        """Two malicious agents sharing an IP -> Multi-stage alert escalated."""
        pivot_ip = "198.51.100.42"
        f_email = AgentFinding(
            agent_id="EmailIntelligenceAgent",
            is_malicious=True,
            risk_score=0.95,
            artifacts=ExtractedArtifacts(ips=[pivot_ip], domains=["patch-update.top"]),
            indicators=["Fake VPN update lure"],
            analyst_summary="Phishing email delivering backdoored binary.",
        )
        f_log = AgentFinding(
            agent_id="BehavioralLogAgent",
            is_malicious=True,
            risk_score=1.0,
            artifacts=ExtractedArtifacts(ips=[pivot_ip], timestamps=["03:12:01"]),
            indicators=["SSH brute-force burst", "Unauthorized sudo execution"],
            analyst_summary="Attacker cracked credentials from pivot IP and escalated privileges.",
        )
        f_ip = AgentFinding(
            agent_id="NetworkReconAgent",
            is_malicious=True,
            risk_score=0.85,
            artifacts=ExtractedArtifacts(ips=[pivot_ip], ports=[22, 80], cves=["CVE-2021-41773"]),
            indicators=["Critical path traversal RCE on Apache 2.4.49"],
            analyst_summary="Target asset exposes critical CVEs.",
        )

        state: ThreatState = {
            "task_id": "APT-CAMPAIGN-001",
            "raw_email": "vpn patch lure",
            "raw_logs": "sshd brute force",
            "target_network": pivot_ip,
            "findings": [f_email, f_log, f_ip],
            "correlation_result": None,
            "audit_trace": [],
        }

        result = asyncio.run(supervisor_correlation_node(state))
        report: CorrelatedIncidentReport = result["correlation_result"]
        assert report.incident_detected is True
        assert report.threat_severity in ["HIGH", "CRITICAL"]
        assert report.confidence_score >= 0.80
        assert pivot_ip in report.common_artifacts.ips
        assert len(report.attack_timeline) > 0
        assert len(report.containment_playbook) > 0
        assert any("Coordinated incident timeline successfully synthesized" in trace for trace in result["audit_trace"])

    def test_full_langgraph_supervision_pipeline(self):
        """End-to-end LangGraph compilation and execution: Email -> Log -> IP -> Supervisor."""
        from langgraph.graph import StateGraph, START, END

        graph = StateGraph(ThreatState)
        graph.add_node("email_agent", email_agent_node)
        graph.add_node("log_agent", log_agent_node)
        graph.add_node("ip_agent", ip_agent_node)
        graph.add_node("supervisor", supervisor_correlation_node)

        graph.add_edge(START, "email_agent")
        graph.add_edge("email_agent", "log_agent")
        graph.add_edge("log_agent", "ip_agent")
        graph.add_edge("ip_agent", "supervisor")
        graph.add_edge("supervisor", END)

        workflow = graph.compile()

        # Coordinated input where 192.168.1.105 appears in email, logs, and IP scan
        coordinated_state = create_initial_threat_state(
            task_id="E2E-APT-001",
            raw_email=(
                "URGENT: Your account credentials have expired. "
                "Authenticate at http://192.168.1.105/auth or access will be revoked within 24 hours."
            ),
            raw_logs=(
                "Oct 10 02:14:01 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22\n"
                "Oct 10 02:14:03 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22\n"
                "Oct 10 02:14:06 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22\n"
                "Oct 10 02:15:10 srv1 sudo: webapp : 3 incorrect password attempts ; TTY=pts/0"
            ),
            target_network="192.168.1.105",
        )

        final_state = asyncio.run(workflow.ainvoke(coordinated_state))

        # Check findings from all 3 workers
        assert len(final_state["findings"]) == 3

        # Check supervisor correlation synthesis
        report: CorrelatedIncidentReport = final_state["correlation_result"]
        assert report is not None
        assert report.incident_detected is True
        assert report.threat_severity in ["HIGH", "CRITICAL"]
        assert report.confidence_score >= 0.80
        assert "192.168.1.105" in report.common_artifacts.ips
        assert len(report.attack_timeline) >= 2
        assert len(report.containment_playbook) >= 1
