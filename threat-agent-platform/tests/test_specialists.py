"""Unit tests for Autonomous Specialist Agents with MITRE ATT&CK Tagging.

Conforms to IEEE Access (Hmimou et al., 2025):
"A Multi-Agent System for Cybersecurity Threat Detection and Correlation Using Large Language Models"
"""

import asyncio
import operator
from pathlib import Path
import sys
import pytest

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

from src.core.state import (
    SwarmState,
    create_initial_swarm_state,
    AgentMessage,
    AgentFinding,
    MitreTechnique,
)
from src.agents.specialists import (
    email_hunter_node,
    log_forensics_node,
    network_recon_node,
)


class TestEmailHunterNode:
    """Tests for email_hunter_node."""

    def test_empty_email_stream(self):
        state = create_initial_swarm_state(raw_email_stream="")
        result = asyncio.run(email_hunter_node(state))

        assert result["next_speaker"] == "supervisor"
        assert "messages" in result
        assert len(result["messages"]) == 1
        msg = result["messages"][0]
        assert msg.sender == "EmailHunter"
        assert msg.recipient == "LeadSupervisor"
        assert "No email telemetry" in msg.content
        assert "specialist_findings" not in result

    def test_phishing_email_detection_and_mitre_tagging(self):
        state = create_initial_swarm_state(
            raw_email_stream=(
                "URGENT: Your account credentials have expired. "
                "Authenticate immediately at http://192.168.1.105/auth or access will be revoked within 24 hours."
            )
        )
        result = asyncio.run(email_hunter_node(state))

        assert result["next_speaker"] == "supervisor"
        assert "specialist_findings" in result
        assert len(result["specialist_findings"]) == 1
        finding = result["specialist_findings"][0]

        assert finding.agent_id == "EmailHunter"
        assert finding.is_malicious is True
        assert 0.0 <= finding.confidence_score <= 1.0
        assert "192.168.1.105" in finding.extracted_entities["ips"]

        # Grounded MITRE ATT&CK tag
        technique_ids = [t.technique_id for t in finding.mitre_tags]
        assert "T1566.002" in technique_ids

        # War-room dialogue message
        assert "messages" in result
        assert len(result["messages"]) == 1
        msg = result["messages"][0]
        assert msg.sender == "EmailHunter"
        assert msg.action_type == "OBSERVE"
        assert "192.168.1.105" in msg.artifacts["ips"]


class TestLogForensicsNode:
    """Tests for log_forensics_node."""

    def test_empty_log_stream(self):
        state = create_initial_swarm_state(raw_log_stream="")
        result = asyncio.run(log_forensics_node(state))

        assert result["next_speaker"] == "supervisor"
        assert "messages" in result
        assert len(result["messages"]) == 1
        msg = result["messages"][0]
        assert msg.sender == "LogForensics"
        assert "No logs in current session buffer" in msg.content
        assert "specialist_findings" not in result

    def test_brute_force_and_sudo_detection(self):
        sample_logs = (
            "Oct 10 02:14:01 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22\n"
            "Oct 10 02:14:03 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22\n"
            "Oct 10 02:14:06 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22\n"
            "Oct 10 02:15:10 srv1 sudo: webapp : 3 incorrect password attempts ; TTY=pts/0"
        )
        state = create_initial_swarm_state(raw_log_stream=sample_logs)
        result = asyncio.run(log_forensics_node(state))

        assert result["next_speaker"] == "supervisor"
        assert "specialist_findings" in result
        assert len(result["specialist_findings"]) == 1
        finding = result["specialist_findings"][0]

        assert finding.agent_id == "LogForensics"
        assert finding.is_malicious is True
        assert 0.0 <= finding.confidence_score <= 1.0
        assert "192.168.1.105" in finding.extracted_entities["ips"]

        # Verify dual MITRE tags: T1110.001 and T1548.003
        technique_ids = [t.technique_id for t in finding.mitre_tags]
        assert "T1110.001" in technique_ids
        assert "T1548.003" in technique_ids

        # Indicators
        assert any("Brute-Force Burst" in ind for ind in finding.technical_indicators)
        assert any("Privilege Escalation Burst" in ind for ind in finding.technical_indicators)

        # War-room message
        assert len(result["messages"]) == 1
        msg = result["messages"][0]
        assert msg.sender == "LogForensics"
        assert "192.168.1.105" in msg.artifacts["ips"]


class TestNetworkReconNode:
    """Tests for network_recon_node."""

    def test_empty_target_and_no_artifacts(self):
        state = create_initial_swarm_state(target_cidr="")
        result = asyncio.run(network_recon_node(state))

        assert result["next_speaker"] == "supervisor"
        assert "messages" in result
        assert len(result["messages"]) == 1
        assert "No network target specified" in result["messages"][0].content
        assert "specialist_findings" not in result

    def test_recon_with_explicit_target(self):
        state = create_initial_swarm_state(target_cidr="192.168.1.105")
        result = asyncio.run(network_recon_node(state))

        assert result["next_speaker"] == "supervisor"
        assert "specialist_findings" in result
        assert len(result["specialist_findings"]) == 1
        finding = result["specialist_findings"][0]

        assert finding.agent_id == "NetworkRecon"
        assert finding.is_malicious is True
        assert finding.confidence_score >= 0.90
        assert "192.168.1.105" in finding.extracted_entities["ips"]
        assert 22 in finding.extracted_entities["ports"]
        assert 80 in finding.extracted_entities["ports"]

        # MITRE ATT&CK tag T1190
        technique_ids = [t.technique_id for t in finding.mitre_tags]
        assert "T1190" in technique_ids

        # High-severity CVE detection
        assert any("CVSS" in ind for ind in finding.technical_indicators)

        # War room message
        assert len(result["messages"]) == 1
        msg = result["messages"][0]
        assert msg.sender == "NetworkRecon"
        assert "192.168.1.105" in msg.artifacts["ips"]
        assert 22 in msg.artifacts["ports"]
        assert len(msg.artifacts["cves"]) > 0

    def test_autonomous_target_recovery_from_war_room_messages(self):
        """Autonomous collaboration: NetworkRecon recovers target IP from prior agent messages."""
        state = create_initial_swarm_state(target_cidr="")
        # Prior email agent posted finding with IP artifact
        prior_msg = AgentMessage(
            sender="EmailHunter",
            recipient="LeadSupervisor",
            content="Phishing URL detected with target host 10.0.0.99",
            action_type="OBSERVE",
            artifacts={"ips": ["10.0.0.99"]},
            timestamp="2026-10-11T12:00:00Z",
        )
        state["messages"].append(prior_msg)

        result = asyncio.run(network_recon_node(state))
        assert "specialist_findings" in result
        finding = result["specialist_findings"][0]
        assert "10.0.0.99" in finding.extracted_entities["ips"]
        assert len(result["messages"]) == 1
        assert "10.0.0.99" in result["messages"][0].artifacts["ips"]


class TestSwarmStateIntegration:
    """Verifies operator.add accumulation across multi-agent execution."""

    def test_state_accumulation_without_overwriting(self):
        state = create_initial_swarm_state(
            raw_email_stream="URGENT: Click http://192.168.1.105/auth within 24 hours.",
            raw_log_stream=(
                "Oct 10 02:14:01 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22\n"
                "Oct 10 02:14:03 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22\n"
                "Oct 10 02:15:10 srv1 sudo: webapp : 3 incorrect password attempts ; TTY=pts/0"
            ),
        )

        # 1. EmailHunter runs
        email_res = asyncio.run(email_hunter_node(state))
        state["messages"] = operator.add(state["messages"], email_res.get("messages", []))
        state["specialist_findings"] = operator.add(
            state["specialist_findings"], email_res.get("specialist_findings", [])
        )

        assert len(state["messages"]) == 1
        assert len(state["specialist_findings"]) == 1

        # 2. LogForensics runs
        log_res = asyncio.run(log_forensics_node(state))
        state["messages"] = operator.add(state["messages"], log_res.get("messages", []))
        state["specialist_findings"] = operator.add(
            state["specialist_findings"], log_res.get("specialist_findings", [])
        )

        assert len(state["messages"]) == 2
        assert len(state["specialist_findings"]) == 2

        # 3. NetworkRecon runs without explicit CIDR, recovering IP from prior messages
        recon_res = asyncio.run(network_recon_node(state))
        state["messages"] = operator.add(state["messages"], recon_res.get("messages", []))
        state["specialist_findings"] = operator.add(
            state["specialist_findings"], recon_res.get("specialist_findings", [])
        )

        assert len(state["messages"]) == 3
        assert len(state["specialist_findings"]) == 3

        agent_ids = [f.agent_id for f in state["specialist_findings"]]
        assert agent_ids == ["EmailHunter", "LogForensics", "NetworkRecon"]
