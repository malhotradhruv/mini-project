"""Unit tests for Dynamic Lead Supervisor and conditional routing logic.

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

from src.core.state import (
    SwarmState,
    create_initial_swarm_state,
    AgentMessage,
    AgentFinding,
    MitreTechnique,
)
from src.core.supervisor import (
    lead_supervisor_node,
    supervisor_router,
)


class TestLeadSupervisorNode:
    """Tests for lead_supervisor_node delegation logic."""

    def test_delegates_to_email_hunter_when_email_stream_present(self):
        state = create_initial_swarm_state(raw_email_stream="URGENT: Verify account at http://phish.top")
        result = asyncio.run(lead_supervisor_node(state))

        assert result["next_speaker"] == "email_hunter"
        assert result["iteration_count"] == 1
        assert len(result["messages"]) == 1
        msg = result["messages"][0]
        assert msg.sender == "LeadSupervisor"
        assert msg.recipient == "EmailHunter"
        assert msg.action_type == "DELEGATE"

    def test_delegates_to_log_forensics_when_email_done_or_absent(self):
        # Email absent, logs present
        state = create_initial_swarm_state(
            raw_email_stream="",
            raw_log_stream="Oct 10 sshd: Failed password for root",
        )
        result = asyncio.run(lead_supervisor_node(state))

        assert result["next_speaker"] == "log_forensics"
        assert result["iteration_count"] == 1
        assert result["messages"][0].recipient == "LogForensics"

    def test_delegates_to_network_recon_when_email_and_log_done(self):
        finding_email = AgentFinding(
            agent_id="EmailHunter",
            is_malicious=True,
            confidence_score=0.9,
            summary="Phishing found",
        )
        finding_log = AgentFinding(
            agent_id="LogForensics",
            is_malicious=True,
            confidence_score=0.85,
            summary="Brute force found",
        )
        state = create_initial_swarm_state(
            raw_email_stream="phish",
            raw_log_stream="logs",
        )
        state["specialist_findings"] = [finding_email, finding_log]
        result = asyncio.run(lead_supervisor_node(state))

        assert result["next_speaker"] == "network_recon"
        assert result["messages"][0].recipient == "NetworkRecon"

    def test_delegates_to_red_team_when_all_specialists_reported(self):
        f_email = AgentFinding(agent_id="EmailHunter", is_malicious=True, confidence_score=0.9, summary="Email")
        f_log = AgentFinding(agent_id="LogForensics", is_malicious=True, confidence_score=0.9, summary="Log")
        f_recon = AgentFinding(agent_id="NetworkRecon", is_malicious=True, confidence_score=0.9, summary="Recon")

        state = create_initial_swarm_state(raw_email_stream="email", raw_log_stream="log")
        state["specialist_findings"] = [f_email, f_log, f_recon]
        state["iteration_count"] = 3

        result = asyncio.run(lead_supervisor_node(state))
        assert result["next_speaker"] == "red_team"
        assert result["messages"][0].recipient == "RedTeamAdversarySim"

    def test_delegates_to_blue_team_after_red_team_has_spoken(self):
        f_email = AgentFinding(agent_id="EmailHunter", is_malicious=True, confidence_score=0.9, summary="Email")
        f_log = AgentFinding(agent_id="LogForensics", is_malicious=True, confidence_score=0.9, summary="Log")
        f_recon = AgentFinding(agent_id="NetworkRecon", is_malicious=True, confidence_score=0.9, summary="Recon")

        red_msg = AgentMessage(
            sender="RedTeamAdversarySim",
            recipient="ALL",
            content="Predicted lateral movement",
            action_type="CHALLENGE",
            timestamp="2026-10-11T12:00:00Z",
        )

        state = create_initial_swarm_state(raw_email_stream="email", raw_log_stream="log")
        state["specialist_findings"] = [f_email, f_log, f_recon]
        state["messages"] = [red_msg]
        state["iteration_count"] = 4

        result = asyncio.run(lead_supervisor_node(state))
        assert result["next_speaker"] == "blue_team"
        assert result["messages"][0].recipient == "BlueTeamCommander"


class TestSupervisorRouter:
    """Tests for conditional edge supervisor_router."""

    def test_terminates_when_consensus_reached(self):
        state = create_initial_swarm_state()
        state["consensus_reached"] = True
        state["next_speaker"] = "blue_team"
        assert supervisor_router(state) == "END"

    def test_terminates_when_next_speaker_is_end(self):
        state = create_initial_swarm_state()
        state["next_speaker"] = "END"
        assert supervisor_router(state) == "END"

    def test_routes_to_specialists(self):
        state = create_initial_swarm_state()
        for speaker in ["email_hunter", "log_forensics", "network_recon", "red_team", "blue_team"]:
            state["next_speaker"] = speaker
            assert supervisor_router(state) == speaker

    def test_defaults_to_supervisor(self):
        state = create_initial_swarm_state()
        state["next_speaker"] = "supervisor"
        assert supervisor_router(state) == "supervisor"

        state["next_speaker"] = "unknown_speaker"
        assert supervisor_router(state) == "supervisor"
