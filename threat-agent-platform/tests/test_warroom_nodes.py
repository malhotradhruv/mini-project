"""Unit tests for Red-Team Adversary Simulator & Blue-Team Commander nodes.

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
    AdversaryHypothesis,
    SwarmIncidentReport,
)
from src.agents.warroom_nodes import (
    red_team_adversary_node,
    blue_team_commander_node,
)
from src.agents.specialists import (
    email_hunter_node,
    log_forensics_node,
    network_recon_node,
)


class TestRedTeamAdversaryNode:
    """Tests for red_team_adversary_node."""

    def test_empty_findings_edge_case(self):
        state = create_initial_swarm_state()
        result = asyncio.run(red_team_adversary_node(state))

        assert result["next_speaker"] == "blue_team"
        assert "messages" in result
        assert len(result["messages"]) == 1

        msg = result["messages"][0]
        assert msg.sender == "RedTeamAdversarySim"
        assert msg.recipient == "ALL"
        assert msg.action_type == "CHALLENGE"
        assert "mitre_tactic" in msg.artifacts

    def test_malicious_findings_trajectory_prediction(self):
        finding = AgentFinding(
            agent_id="LogForensics",
            is_malicious=True,
            confidence_score=0.92,
            mitre_tags=[
                MitreTechnique(technique_id="T1110.001", tactic="Credential Access", description="Password Guessing")
            ],
            technical_indicators=["SSH brute-force burst from 192.168.1.105"],
            extracted_entities={"ips": ["192.168.1.105"], "domains": [], "ports": [], "cves": []},
            summary="Attacker successfully compromised deploy credentials via SSH brute-force.",
        )
        state = create_initial_swarm_state()
        state["specialist_findings"].append(finding)

        result = asyncio.run(red_team_adversary_node(state))
        assert result["next_speaker"] == "blue_team"
        assert len(result["messages"]) == 1

        msg = result["messages"][0]
        assert msg.sender == "RedTeamAdversarySim"
        assert msg.action_type == "CHALLENGE"
        assert "hypothesis" in msg.artifacts
        assert len(msg.artifacts["mitre_tactic"]) > 0


class TestBlueTeamCommanderNode:
    """Tests for blue_team_commander_node."""

    def test_empty_findings_edge_case(self):
        state = create_initial_swarm_state()
        result = asyncio.run(blue_team_commander_node(state))

        assert result["next_speaker"] == "END"
        assert result["consensus_reached"] is True
        assert len(result["messages"]) == 1

        msg = result["messages"][0]
        assert msg.sender == "BlueTeamCommander"
        assert msg.action_type == "VERIFY"
        assert len(msg.artifacts["commands"]) == 5

        report: SwarmIncidentReport = result["final_incident_report"]
        assert report.incident_active is False
        assert report.threat_severity == "BENIGN"
        assert report.consensus_confidence <= 0.20
        assert len(report.containment_commands) == 5

    def test_critical_breach_containment_and_consensus(self):
        finding_email = AgentFinding(
            agent_id="EmailHunter",
            is_malicious=True,
            confidence_score=0.88,
            mitre_tags=[
                MitreTechnique(technique_id="T1566.002", tactic="Initial Access", description="Spearphishing Link")
            ],
            technical_indicators=["Phishing URL with credential harvesting"],
            extracted_entities={"ips": ["192.168.1.105"], "domains": ["login-portal.top"], "ports": [], "cves": []},
            summary="Discovered phishing campaign from 192.168.1.105.",
        )
        finding_recon = AgentFinding(
            agent_id="NetworkRecon",
            is_malicious=True,
            confidence_score=0.91,
            mitre_tags=[
                MitreTechnique(technique_id="T1190", tactic="Initial Access", description="Exploit Public-Facing Application")
            ],
            technical_indicators=["Port 80 Apache 2.4.49 (CVE-2021-41773)"],
            extracted_entities={"ips": ["192.168.1.105"], "domains": [], "ports": [22, 80], "cves": ["CVE-2021-41773"]},
            summary="High-severity unpatched CVEs on target.",
        )

        state = create_initial_swarm_state()
        state["specialist_findings"] = [finding_email, finding_recon]

        # Add simulated red-team trajectory message
        red_msg = AgentMessage(
            sender="RedTeamAdversarySim",
            recipient="ALL",
            content="⚠️ ADVERSARY TRAJECTORY: Attacker will execute RCE via CVE-2021-41773.",
            action_type="CHALLENGE",
            artifacts={
                "mitre_tactic": "Execution",
                "hypothesis": {
                    "predicted_next_step": "Path traversal execution on port 80",
                    "target_asset": "192.168.1.105:80",
                    "mitre_tactic": "Execution",
                    "exploit_vector": "CVE-2021-41773",
                },
            },
            timestamp="2026-10-11T12:00:00Z",
        )
        state["messages"].append(red_msg)

        result = asyncio.run(blue_team_commander_node(state))

        assert result["consensus_reached"] is True
        assert result["next_speaker"] == "END"

        report: SwarmIncidentReport = result["final_incident_report"]
        assert report.incident_active is True
        assert report.threat_severity == "CRITICAL"
        assert report.consensus_confidence >= 0.90
        assert "192.168.1.105" in report.correlated_entities["ips"]

        # Containment commands check
        assert any("iptables -A INPUT -s 192.168.1.105 -j DROP" in cmd for cmd in report.containment_commands)
        assert any("fail2ban-client" in cmd for cmd in report.containment_commands)
        assert any("systemctl restart sshd" in cmd for cmd in report.containment_commands)

        # Adversary trajectory linked from Red Team
        assert report.adversary_trajectory is not None
        assert report.adversary_trajectory.mitre_tactic == "Execution"
        assert report.adversary_trajectory.exploit_vector == "CVE-2021-41773"


class TestFullWarRoomExecutionChain:
    """Verifies complete end-to-end swarm execution across all 5 agents."""

    def test_e2e_warroom_chain(self):
        state = create_initial_swarm_state(
            raw_email_stream="URGENT: Click http://192.168.1.105/auth within 24 hours.",
            raw_log_stream=(
                "Oct 10 02:14:01 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22\n"
                "Oct 10 02:14:03 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22\n"
                "Oct 10 02:15:10 srv1 sudo: webapp : 3 incorrect password attempts ; TTY=pts/0"
            ),
        )

        # 1. EmailHunter
        email_out = asyncio.run(email_hunter_node(state))
        state["messages"] = operator.add(state["messages"], email_out.get("messages", []))
        state["specialist_findings"] = operator.add(
            state["specialist_findings"], email_out.get("specialist_findings", [])
        )

        # 2. LogForensics
        log_out = asyncio.run(log_forensics_node(state))
        state["messages"] = operator.add(state["messages"], log_out.get("messages", []))
        state["specialist_findings"] = operator.add(
            state["specialist_findings"], log_out.get("specialist_findings", [])
        )

        # 3. NetworkRecon (Autonomous target recovery)
        recon_out = asyncio.run(network_recon_node(state))
        state["messages"] = operator.add(state["messages"], recon_out.get("messages", []))
        state["specialist_findings"] = operator.add(
            state["specialist_findings"], recon_out.get("specialist_findings", [])
        )

        # 4. RedTeamAdversarySim
        red_out = asyncio.run(red_team_adversary_node(state))
        state["messages"] = operator.add(state["messages"], red_out.get("messages", []))

        # 5. BlueTeamCommander
        blue_out = asyncio.run(blue_team_commander_node(state))
        state["messages"] = operator.add(state["messages"], blue_out.get("messages", []))
        state["final_incident_report"] = blue_out["final_incident_report"]
        state["consensus_reached"] = blue_out["consensus_reached"]

        assert state["consensus_reached"] is True
        assert len(state["messages"]) == 5
        assert len(state["specialist_findings"]) == 3

        report: SwarmIncidentReport = state["final_incident_report"]
        assert report.incident_active is True
        assert report.threat_severity == "CRITICAL"
        assert report.consensus_confidence >= 0.90
        assert "192.168.1.105" in report.correlated_entities["ips"]
        assert len(report.containment_commands) >= 5
        assert report.adversary_trajectory is not None
