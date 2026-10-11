"""Core orchestration, LLM gateway, and correlation engine."""
from .llm_gateway import LLMGateway
from .correlator import ContextualCorrelator, ThreatCorrelator, supervisor_correlation_node


from .state import (
    ExtractedArtifacts,
    AgentFinding,
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
    "ExtractedArtifacts",
    "AgentFinding",
    "AttackStage",
    "CorrelatedIncidentReport",
    "ThreatState",
    "create_initial_threat_state",
]


