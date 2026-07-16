"""agent-audit — Cryptographically-linked records of AI agent tool calls.

See SCOPE_STATEMENT.md before staking a compliance claim on v0.1.
"""

from agent_audit.adapters.langgraph import audited_tool
from agent_audit.emit import AuditRecorder, RecordBuildError, RecordSigningError
from agent_audit.keys import SigningKey, load_public_key, load_signing_key
from agent_audit.manifest import ChainState, FileChecksum, Manifest
from agent_audit.redact import DEFAULT_RULES, RedactionConfig, RedactionRule
from agent_audit.schema.v1 import (
    Gate,
    GateDecision,
    LifecycleEventPayload,
    LifecyclePhase,
    LifecycleRecord,
    LifecycleTransition,
    NodeTransition,
    NoGateReason,
    Output,
    PolicyUnobservedReason,
    RouteTransition,
    ToolCall,
    Ungated,
    UnobservedPolicy,
    gate,
    node_transition,
    policy_unobserved,
    route_transition,
    ungated,
)
from agent_audit.sinks.base import (
    DiskFullError,
    InMemorySink,
    Sink,
    SinkError,
)
from agent_audit.sinks.local_file import LocalFileSink

__version__ = "0.1.2"

__all__ = [
    "AuditRecorder",
    "ChainState",
    "DEFAULT_RULES",
    "DiskFullError",
    "FileChecksum",
    "Gate",
    "GateDecision",
    "InMemorySink",
    "LifecycleEventPayload",
    "LifecyclePhase",
    "LifecycleRecord",
    "LifecycleTransition",
    "LocalFileSink",
    "Manifest",
    "NoGateReason",
    "NodeTransition",
    "Output",
    "PolicyUnobservedReason",
    "RecordBuildError",
    "RecordSigningError",
    "RedactionConfig",
    "RedactionRule",
    "RouteTransition",
    "Sink",
    "SinkError",
    "SigningKey",
    "ToolCall",
    "Ungated",
    "UnobservedPolicy",
    "__version__",
    "audited_tool",
    "gate",
    "load_public_key",
    "load_signing_key",
    "node_transition",
    "policy_unobserved",
    "route_transition",
    "ungated",
]
