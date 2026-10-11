"""Unit and Integration tests for compiled LangGraph SOC workflow.

Conforms to IEEE Access (Hmimou et al., 2025):
"A Multi-Agent System for Cybersecurity Threat Detection and Correlation Using Large Language Models"
"""

import asyncio
from pathlib import Path
import sys
import pytest

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

from src.core.graph import create_multi_agent_soc_graph
from src.core.state import create_initial_threat_state, ThreatState


class TestMultiAgentSOCGraph:
    """Validation for StateGraph compilation and execution."""

    def test_graph_compilation_and_nodes(self):
        """Verify the graph compiles properly and registers all required nodes."""
        app = create_multi_agent_soc_graph()
        assert app is not None
        # Verify node registration in graph
        nodes = app.get_graph().nodes
        assert "email_worker" in nodes
        assert "log_worker" in nodes
        assert "ip_worker" in nodes
        assert "supervisor_correlator" in nodes

    def test_graph_empty_inputs(self):
        """Empty input payloads should gracefully skip without exceptions."""
        app = create_multi_agent_soc_graph()
        initial_state = create_initial_threat_state(task_id="EMPTY-TEST-001")
        final_state: ThreatState = asyncio.run(app.ainvoke(initial_state))

        assert len(final_state["findings"]) == 0
        assert final_state["correlation_result"] is not None
        assert final_state["correlation_result"].incident_detected is False
        assert any("Skipping" in trace for trace in final_state["audit_trace"])

    def test_graph_isolated_threats_suppress_correlation(self):
        """Isolated threats without shared IOCs should not trigger multi-stage alarm."""
        app = create_multi_agent_soc_graph()
        initial_state = create_initial_threat_state(
            task_id="ISOLATED-001",
            raw_email="URGENT: Verify your account immediately at http://192.0.2.1/login.php",
            raw_logs="Oct 10 02:14:01 srv1 sshd[102]: Failed password for root from 10.0.0.5 port 22\nOct 10 02:14:02 srv1 sshd[102]: Failed password for root from 10.0.0.5 port 22\nOct 10 02:14:03 srv1 sshd[102]: Failed password for root from 10.0.0.5 port 22",
            target_network="172.16.0.1",
        )
        final_state: ThreatState = asyncio.run(app.ainvoke(initial_state))

        report = final_state["correlation_result"]
        assert report is not None
        # Disjoint IPs: 192.0.2.1 vs 10.0.0.5 vs 172.16.0.1 -> No common IP
        assert len(report.common_artifacts.ips) == 0
        assert report.incident_detected is False
        assert report.threat_severity == "LOW"

    def test_graph_coordinated_multi_stage_attack(self):
        """Coordinated attack with shared pivot IP should produce correlation report."""
        app = create_multi_agent_soc_graph()
        initial_state = create_initial_threat_state(
            task_id="COORDINATED-001",
            raw_email=(
                "URGENT: Critical security update required immediately. "
                "Download security patch from http://192.168.1.105/patch.php "
                "or your workstation will be locked within 24 hours. IT Support."
            ),
            raw_logs=(
                "Oct 10 02:14:01 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22\n"
                "Oct 10 02:14:03 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22\n"
                "Oct 10 02:14:05 srv1 sshd[102]: Accepted password for root from 192.168.1.105 port 22\n"
                "Oct 10 02:14:10 srv1 sudo: pam_unix(sudo:session): session opened for user root by (uid=0)"
            ),
            target_network="192.168.1.105",
        )
        final_state: ThreatState = asyncio.run(app.ainvoke(initial_state))

        findings = final_state["findings"]
        report = final_state["correlation_result"]

        assert len(findings) == 3
        assert all(f.is_malicious for f in findings)
        assert report is not None
        assert report.incident_detected is True
        assert report.threat_severity in ["HIGH", "CRITICAL"]
        assert "192.168.1.105" in report.common_artifacts.ips
        assert len(report.attack_timeline) >= 2
        assert len(report.containment_playbook) >= 1
