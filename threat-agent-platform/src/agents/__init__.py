"""Specialized detection agents, LangGraph worker nodes, autonomous specialists, and war-room simulators."""
from .email_agent import EmailAgent, email_agent_node
from .log_agent import LogAgent, log_agent_node
from .ip_agent import IPAgent, ip_agent_node
from .specialists import (
    email_hunter_node,
    log_forensics_node,
    network_recon_node,
)
from .warroom_nodes import (
    red_team_adversary_node,
    blue_team_commander_node,
)

__all__ = [
    # Legacy Stage 1 Worker Nodes
    "EmailAgent",
    "LogAgent",
    "IPAgent",
    "email_agent_node",
    "log_agent_node",
    "ip_agent_node",
    # Autonomous Swarm Specialist Nodes
    "email_hunter_node",
    "log_forensics_node",
    "network_recon_node",
    # War-Room Adversarial & Defense Nodes
    "red_team_adversary_node",
    "blue_team_commander_node",
]
