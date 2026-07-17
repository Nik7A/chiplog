"""chiplog — Cryptographically-linked records of AI agent tool calls.

See SCOPE_STATEMENT.md before staking a compliance claim on v0.1.
"""

from importlib.metadata import version as _dist_version

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

# Derived, never hand-written: the number lives once, in the packaging config.
# A literal here went two releases stale (0.1.2 while the dist was 0.2.1)
# because every release had to remember to touch it. See
# tests/test_version_single_source.py.
__version__ = _dist_version("chiplog")

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
