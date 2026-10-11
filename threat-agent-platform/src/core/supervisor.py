"""Dynamic Lead Supervisor & Orchestration Router.

Conforms to IEEE Access (Hmimou et al., 2025):
"A Multi-Agent System for Cybersecurity Threat Detection and Correlation Using Large Language Models"

Components:
1. lead_supervisor_node: Conductor of the SOC war room that inspects dialogue state,
   delegates to domain specialists, summons the Red-Team simulator, and tasks the
   Blue-Team commander for containment.
2. supervisor_router: Conditional edge router for LangGraph cyclic state machines that
   cleanly terminates execution when consensus is reached.
"""

import os
import json
import datetime
from typing import Dict, Any
from dotenv import load_dotenv
from langchain_groq import ChatGroq

from src.core.state import SwarmState, AgentMessage

load_dotenv()

_groq_key = os.getenv("GROQ_API_KEY") or "gsk_placeholder_for_offline_eval"
llm = ChatGroq(model_name="llama-3.3-70b-versatile", temperature=0.1, groq_api_key=_groq_key)


def _get_utc_timestamp() -> str:
    """Returns current UTC timestamp in ISO-8601 format."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


async def lead_supervisor_node(state: SwarmState) -> dict:
    """Dynamic central orchestrator managing war-room delegations and consensus transitions."""
    messages = state.get("messages", []) or []
    findings = state.get("specialist_findings", []) or []
    iteration = state.get("iteration_count", 0) + 1
    now = _get_utc_timestamp()

    # Track who has already reported (both via findings and war-room messages)
    reported_agents = {
        getattr(f, "agent_id", "") if hasattr(f, "agent_id") else (f.get("agent_id", "") if isinstance(f, dict) else "")
        for f in findings
    }
    for m in messages:
        sender = getattr(m, "sender", "") if hasattr(m, "sender") else (m.get("sender", "") if isinstance(m, dict) else "")
        if sender:
            reported_agents.add(sender)

    # 1. Bootstrapping: Delegate to specialists who haven't run yet
    if "EmailHunter" not in reported_agents and state.get("raw_email_stream"):
        msg = AgentMessage(
            sender="LeadSupervisor",
            recipient="EmailHunter",
            content="EmailHunter, inspect the inbound email payload for spoofing and phishing indicators.",
            action_type="DELEGATE",
            timestamp=now,
        )
        return {"messages": [msg], "next_speaker": "email_hunter", "iteration_count": iteration}

    if "LogForensics" not in reported_agents and state.get("raw_log_stream"):
        msg = AgentMessage(
            sender="LeadSupervisor",
            recipient="LogForensics",
            content="LogForensics, examine system auth logs for brute-force bursts and privilege escalation attempts.",
            action_type="DELEGATE",
            timestamp=now,
        )
        return {"messages": [msg], "next_speaker": "log_forensics", "iteration_count": iteration}

    if "NetworkRecon" not in reported_agents:
        msg = AgentMessage(
            sender="LeadSupervisor",
            recipient="NetworkRecon",
            content="NetworkRecon, audit the network attack surface for exposed daemons and known CVEs.",
            action_type="DELEGATE",
            timestamp=now,
        )
        return {"messages": [msg], "next_speaker": "network_recon", "iteration_count": iteration}

    # 2. Once all specialists have reported, call Red-Team Simulation
    red_team_spoken = any(
        getattr(m, "sender", "") == "RedTeamAdversarySim"
        or (isinstance(m, dict) and m.get("sender") == "RedTeamAdversarySim")
        for m in messages
    )
    if not red_team_spoken and iteration <= 4:
        msg = AgentMessage(
            sender="LeadSupervisor",
            recipient="RedTeamAdversarySim",
            content="Specialist evidence collected. Red-Team Simulator, project the attacker's next move and targets.",
            action_type="DELEGATE",
            timestamp=now,
        )
        return {"messages": [msg], "next_speaker": "red_team", "iteration_count": iteration}

    # 3. Finalize: Call Blue-Team Commander to lock in containment
    msg = AgentMessage(
        sender="LeadSupervisor",
        recipient="BlueTeamCommander",
        content="Adversary trajectory analyzed. BlueTeamCommander, finalize incident consensus and generate containment playbooks.",
        action_type="DELEGATE",
        timestamp=now,
    )
    return {"messages": [msg], "next_speaker": "blue_team", "iteration_count": iteration}


def supervisor_router(state: SwarmState) -> str:
    """Conditional Edge function for LangGraph cyclic workflow."""
    if state.get("consensus_reached", False) or state.get("next_speaker") == "END":
        return "END"
    if state.get("iteration_count", 0) >= state.get("max_iterations", 8):
        return "END"

    speaker = state.get("next_speaker", "supervisor")
    if speaker in ["email_hunter", "log_forensics", "network_recon", "red_team", "blue_team"]:
        return speaker
    return "supervisor"


__all__ = [
    "lead_supervisor_node",
    "supervisor_router",
]
