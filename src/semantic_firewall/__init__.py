"""ECS Guardian Semantic — Semantic Pipeline Vulnerability Filter."""

__version__ = "0.1.0"

from semantic_firewall.engine.guard import SemanticFirewallDenied, require_clearance
from semantic_firewall.engine.pipeline import inspect_message
from semantic_firewall.schema import (
    Channel,
    DecisionEffect,
    InspectRequest,
    InspectVerdict,
    ThreatType,
)

__all__ = [
    "Channel",
    "DecisionEffect",
    "InspectRequest",
    "InspectVerdict",
    "SemanticFirewallDenied",
    "ThreatType",
    "inspect_message",
    "require_clearance",
    "__version__",
]
