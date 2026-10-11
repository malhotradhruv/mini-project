"""Core orchestration, LLM gateway, correlation engine, authentication, and compiled swarm graphs."""
from .llm_gateway import LLMGateway
from .correlator import ContextualCorrelator, ThreatCorrelator, supervisor_correlation_node
from .supervisor import lead_supervisor_node, supervisor_router
from .swarm_graph import build_cyber_warroom_swarm
from .auth import AuthService, get_current_user, require_role

from .state import (
    AgentMessage,
    MitreTechnique,
    AgentFinding,
    AdversaryHypothesis,
    SwarmIncidentReport,
    SwarmState,
    create_initial_swarm_state,
    ExtractedArtifacts,
    AttackStage,
    CorrelatedIncidentReport,
    ThreatState,
    create_initial_threat_state,
)

from .graph import create_multi_agent_soc_graph


def __getattr__(name: str):
    if name == "TaskDispatcher":
        from .dispatcher import TaskDispatcher
        return TaskDispatcher
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "LLMGateway",
    "TaskDispatcher",
    "ContextualCorrelator",
    "ThreatCorrelator",
    "supervisor_correlation_node",
    "create_multi_agent_soc_graph",
    # Dynamic Supervisor & Swarm StateGraph
    "lead_supervisor_node",
    "supervisor_router",
    "build_cyber_warroom_swarm",
    # Enterprise Authentication
    "AuthService",
    "get_current_user",
    "require_role",
    # Autonomous Swarm Protocols
    "AgentMessage",
    "MitreTechnique",
    "AgentFinding",
    "AdversaryHypothesis",
    "SwarmIncidentReport",
    "SwarmState",
    "create_initial_swarm_state",
    # Legacy Protocols
    "ExtractedArtifacts",
    "AttackStage",
    "CorrelatedIncidentReport",
    "ThreatState",
    "create_initial_threat_state",
]
