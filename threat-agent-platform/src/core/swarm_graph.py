"""Compiled Cyclic Multi-Agent Swarm Graph.

Conforms to IEEE Access (Hmimou et al., 2025):
"A Multi-Agent System for Cybersecurity Threat Detection and Correlation Using Large Language Models"

Assembles:
1. Dynamic Supervisor Orchestrator (lead_supervisor_node, supervisor_router)
2. Domain Forensic Specialists (EmailHunter, LogForensics, NetworkRecon)
3. War-Room Adversarial Simulation & Defense (RedTeamAdversarySim, BlueTeamCommander)
"""

from langgraph.graph import StateGraph, END
from src.core.state import SwarmState
from src.core.supervisor import lead_supervisor_node, supervisor_router
from src.agents.specialists import email_hunter_node, log_forensics_node, network_recon_node
from src.agents.warroom_nodes import red_team_adversary_node, blue_team_commander_node


def build_cyber_warroom_swarm():
    """Build and compile the cyclic autonomous cyber war-room StateGraph."""
    workflow = StateGraph(SwarmState)

    # 1. Register Nodes
    workflow.add_node("supervisor", lead_supervisor_node)
    workflow.add_node("email_hunter", email_hunter_node)
    workflow.add_node("log_forensics", log_forensics_node)
    workflow.add_node("network_recon", network_recon_node)
    workflow.add_node("red_team", red_team_adversary_node)
    workflow.add_node("blue_team", blue_team_commander_node)

    # 2. Entry Point
    workflow.set_entry_point("supervisor")

    # 3. Dynamic Routing from Supervisor
    workflow.add_conditional_edges(
        "supervisor",
        supervisor_router,
        {
            "email_hunter": "email_hunter",
            "log_forensics": "log_forensics",
            "network_recon": "network_recon",
            "red_team": "red_team",
            "blue_team": "blue_team",
            "END": END,
        },
    )

    # 4. Specialists loop back to Supervisor for next delegation
    workflow.add_edge("email_hunter", "supervisor")
    workflow.add_edge("log_forensics", "supervisor")
    workflow.add_edge("network_recon", "supervisor")

    # 5. Red-Team transitions to Blue-Team for immediate containment
    workflow.add_edge("red_team", "blue_team")
    workflow.add_edge("blue_team", END)

    return workflow.compile()


__all__ = [
    "build_cyber_warroom_swarm",
]
