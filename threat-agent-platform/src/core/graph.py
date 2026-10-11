"""Compiled LangGraph Workflow for Multi-Agent SOC Platform.

Based on the IEEE Access research paper:
"A Multi-Agent System for Cybersecurity Threat Detection and Correlation Using Large Language Models"
(Hmimou et al., 2025).

Assembles the worker nodes (Email, Log, Network/IP) and the cross-domain correlation
supervisor into an asynchronous, reproducible LangGraph StateGraph.
"""

from typing import Any
from langgraph.graph import StateGraph, END
from src.core.state import ThreatState
from src.agents.email_agent import email_agent_node
from src.agents.log_agent import log_agent_node
from src.agents.ip_agent import ip_agent_node
from src.core.correlator import supervisor_correlation_node


def create_multi_agent_soc_graph():
    """Build and compile the multi-agent SOC StateGraph.

    Architecture:
    1. Worker Nodes:
       - email_worker: Deterministic DNS + sentiment + phishing RAG + LLM analysis
       - log_worker: Regex auth logs + failed logins / sudo abuse heuristics + LLM analysis
       - ip_worker: Nmap port banner / NIST CVE mapping + LLM analysis
    2. Supervisor Node:
       - supervisor_correlator: Programmatic entity intersection (IP_email n IP_log n IP_network)
         + multi-stage MITRE ATT&CK timeline synthesis and containment playbook generation.

    Edges:
    email_worker -> log_worker -> ip_worker -> supervisor_correlator -> END
    """
    graph = StateGraph(ThreatState)

    # 1. Register Worker & Supervisor Nodes
    graph.add_node("email_worker", email_agent_node)
    graph.add_node("log_worker", log_agent_node)
    graph.add_node("ip_worker", ip_agent_node)
    graph.add_node("supervisor_correlator", supervisor_correlation_node)

    # 2. Wire Control Flow (Entry -> Workers -> Supervisor -> END)
    graph.set_entry_point("email_worker")
    graph.add_edge("email_worker", "log_worker")
    graph.add_edge("log_worker", "ip_worker")
    graph.add_edge("ip_worker", "supervisor_correlator")
    graph.add_edge("supervisor_correlator", END)

    return graph.compile()


__all__ = [
    "create_multi_agent_soc_graph",
]
