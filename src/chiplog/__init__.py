"""chiplog — Cryptographically-linked records of AI agent tool calls.

See SCOPE_STATEMENT.md before staking a compliance claim on v0.1.
"""

from chiplog.adapters.langgraph import audited_tool
from chiplog.emit import AuditRecorder, RecordBuildError, RecordSigningError
from chiplog.keys import SigningKey, load_public_key, load_signing_key
from chiplog.manifest import ChainState, FileChecksum, Manifest
from chiplog.redact import DEFAULT_RULES, RedactionConfig, RedactionRule
from chiplog.schema.v1 import (
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
from chiplog.sinks.base import (
    DiskFullError,
    InMemorySink,
    Sink,
    SinkError,
)
from chiplog.sinks.local_file import LocalFileSink

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
