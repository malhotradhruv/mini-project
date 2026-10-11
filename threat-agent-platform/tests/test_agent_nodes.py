"""Unit tests for LangGraph worker nodes (email_agent_node, log_agent_node, ip_agent_node).

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

from src.core.state import ThreatState, create_initial_threat_state
from src.agents.email_agent import email_agent_node
from src.agents.log_agent import log_agent_node
from src.agents.ip_agent import ip_agent_node


class TestEmailAgentNode:
    """Tests for email_agent_node."""

    def test_empty_email_payload(self):
        state = create_initial_threat_state(raw_email="")
        result = asyncio.run(email_agent_node(state))
        assert "audit_trace" in result
        assert any("Empty payload" in trace for trace in result["audit_trace"])
        assert "findings" not in result

    def test_phishing_email_detection(self):
        state = create_initial_threat_state(
            raw_email=(
                "URGENT: Your account credentials have expired. "
                "Authenticate immediately at http://192.168.1.105/auth or access will be revoked within 24 hours."
            )
        )
        result = asyncio.run(email_agent_node(state))
        assert "findings" in result
        assert len(result["findings"]) == 1
        finding = result["findings"][0]
        assert finding.agent_id == "EmailIntelligenceAgent"
        assert finding.is_malicious is True
        assert finding.risk_score >= 0.70
        assert "192.168.1.105" in finding.artifacts.ips
        assert len(finding.indicators) > 0
        assert any("EmailAgent completed" in trace for trace in result["audit_trace"])


class TestLogAgentNode:
    """Tests for log_agent_node."""

    def test_empty_logs_payload(self):
        state = create_initial_threat_state(raw_logs="")
        result = asyncio.run(log_agent_node(state))
        assert "audit_trace" in result
        assert any("No logs provided" in trace for trace in result["audit_trace"])
        assert "findings" not in result

    def test_brute_force_and_sudo_detection(self):
        sample_logs = (
            "Oct 10 02:14:01 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22\n"
            "Oct 10 02:14:03 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22\n"
            "Oct 10 02:14:06 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22\n"
            "Oct 10 02:15:10 srv1 sudo: webapp : 3 incorrect password attempts ; TTY=pts/0"
        )
        state = create_initial_threat_state(raw_logs=sample_logs)
        result = asyncio.run(log_agent_node(state))
        assert "findings" in result
        assert len(result["findings"]) == 1
        finding = result["findings"][0]
        assert finding.agent_id == "BehavioralLogAgent"
        assert finding.is_malicious is True
        assert finding.risk_score >= 0.70
        assert "192.168.1.105" in finding.artifacts.ips
        assert any("Brute force" in ind for ind in finding.indicators)
        assert any("Privilege escalation" in ind for ind in finding.indicators)


class TestIPAgentNode:
    """Tests for ip_agent_node."""

    def test_missing_target_host(self):
        state = create_initial_threat_state(target_network="")
        result = asyncio.run(ip_agent_node(state))
        assert "audit_trace" in result
        assert any("Target host missing" in trace for trace in result["audit_trace"])
        assert "findings" not in result

    def test_invalid_target_syntax(self):
        state = create_initial_threat_state(target_network="not-a-valid-ip-or-cidr")
        result = asyncio.run(ip_agent_node(state))
        assert "audit_trace" in result
        assert any("Target input syntax invalid" in trace for trace in result["audit_trace"])
        assert "findings" not in result

    def test_network_recon_and_vulnerability_mapping(self):
        state = create_initial_threat_state(target_network="192.168.1.105")
        result = asyncio.run(ip_agent_node(state))
        assert "findings" in result
        assert len(result["findings"]) == 1
        finding = result["findings"][0]
        assert finding.agent_id == "NetworkReconAgent"
        assert finding.artifacts.ips == ["192.168.1.105"]
        assert len(finding.artifacts.ports) > 0
        assert len(finding.artifacts.cves) > 0
        assert any("IPAgent completed" in trace for trace in result["audit_trace"])


class TestLangGraphThreeNodeIntegration:
    """Tests integrating all three agent nodes into a single LangGraph StateGraph."""

    def test_full_three_agent_graph(self):
        from langgraph.graph import StateGraph, START, END

        graph = StateGraph(ThreatState)
        graph.add_node("email_agent", email_agent_node)
        graph.add_node("log_agent", log_agent_node)
        graph.add_node("ip_agent", ip_agent_node)

        graph.add_edge(START, "email_agent")
        graph.add_edge("email_agent", "log_agent")
        graph.add_edge("log_agent", "ip_agent")
        graph.add_edge("ip_agent", END)

        workflow = graph.compile()
        initial_state = create_initial_threat_state(
            task_id="E2E-CAMPAIGN-001",
            raw_email="URGENT: Click http://192.168.1.105/auth within 24 hours.",
            raw_logs=(
                "Oct 10 02:14:01 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22\n"
                "Oct 10 02:14:03 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22\n"
                "Oct 10 02:14:06 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22"
            ),
            target_network="192.168.1.105",
        )

        final_state = asyncio.run(workflow.ainvoke(initial_state))

        # Verify all 3 worker nodes appended their findings
        assert len(final_state["findings"]) == 3
        agent_names = {f.agent_id for f in final_state["findings"]}
        assert "EmailIntelligenceAgent" in agent_names
        assert "BehavioralLogAgent" in agent_names
        assert "NetworkReconAgent" in agent_names

        # Verify all 3 worker nodes appended to audit_trace
        assert len(final_state["audit_trace"]) == 3
        assert any("EmailAgent completed" in t for t in final_state["audit_trace"])
        assert any("LogAgent completed" in t for t in final_state["audit_trace"])
        assert any("IPAgent completed" in t for t in final_state["audit_trace"])
